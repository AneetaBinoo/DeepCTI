"""Fetch the real vendor files used by D7 `vendor` fixtures for every planned (product, version).

Tomcat: official binary tarball from archive.apache.org (RELEASE-NOTES, RUNNING.txt, NOTICE, conf/*.xml|properties)
httpd:  official source tarball from archive.apache.org (include/ap_release.h, docs/conf/httpd.conf.in ->
        httpd.conf with the install-time substitutions of `make install` for --prefix=/opt/httpd)
Roundcube: files at the release tag from GitHub (program/include/iniset.php, CHANGELOG.md, README.md)
GitLab: VERSION at the v<version>-ee tag from gitlab.com
Jenkins: nothing to fetch (JENKINS_HOME files are generated in the Jenkins format)

Tarballs are streamed and only the listed members are kept (data/cache/vendorx/<product>/<version>/);
URL, sha256 of the downloaded archive and retrieval time go to data/mirrors/vendor_files/<date>/MANIFEST.json.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, Manifest, fetch_cached, now_iso  # noqa: E402
from d7common import CUR, load_json  # noqa: E402

VX = DATA / "cache" / "vendorx"
UA = {"User-Agent": "DeepCTI-research-dataset/2.0 (academic)"}
HTTPD_ENABLED = ["authn_file", "authn_core", "authz_host", "authz_groupfile", "authz_user", "authz_core",
                 "access_compat", "auth_basic", "reqtimeout", "filter", "mime", "log_config", "env", "headers",
                 "setenvif", "version", "unixd", "status", "autoindex", "dir", "alias"]
HTTPD_DISABLED = ["authn_dbm", "authn_anon", "authn_dbd", "authn_socache", "authz_dbm", "authz_owner", "authz_dbd",
                  "auth_form", "auth_digest", "allowmethods", "file_cache", "cache", "cache_disk", "cache_socache",
                  "socache_shmcb", "socache_dbm", "socache_memcache", "watchdog", "macro", "dbd", "dumpio",
                  "buffer", "ratelimit", "ext_filter", "include", "substitute", "sed", "deflate", "logio",
                  "expires", "unique_id", "proxy", "proxy_connect", "proxy_ftp", "proxy_http", "proxy_fcgi",
                  "proxy_scgi", "proxy_uwsgi", "proxy_fdpass", "proxy_wstunnel", "proxy_ajp", "proxy_balancer",
                  "proxy_express", "proxy_hcheck", "session", "session_cookie", "session_dbd", "slotmem_shm",
                  "ssl", "lbmethod_byrequests", "lbmethod_bytraffic", "lbmethod_bybusyness", "lbmethod_heartbeat",
                  "dav", "info", "cgid", "dav_fs", "vhost_alias", "negotiation", "actions", "speling", "userdir",
                  "rewrite"]


def stream_tar(url: str, want, man: Manifest, dest: Path) -> dict:
    h = hashlib.sha256()
    n = 0
    got = {}

    class Tee:
        def __init__(self, raw):
            self.raw = raw

        def read(self, k=-1):
            nonlocal n
            b = self.raw.read(k)
            h.update(b)
            n += len(b)
            return b

    with requests.get(url, stream=True, timeout=600, headers=UA) as r:
        r.raise_for_status()
        mode = "r|bz2" if url.endswith(".bz2") else "r|gz"
        with tarfile.open(fileobj=Tee(r.raw), mode=mode) as tf:
            for m in tf:
                rel = want(m.name)
                if rel and m.isfile():
                    data = tf.extractfile(m).read()
                    (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                    (dest / rel).write_bytes(data)
                    got[rel] = len(data)
        # drain the rest so the hash covers the whole archive
        while r.raw.read(1 << 20):
            pass
    man.add_remote(url, h.hexdigest(), n, files=sorted(got))
    return got


class VManifest(Manifest):
    def add_remote(self, url: str, sha: str, size: int, **extra) -> None:
        with self.lock:
            self.data["files"][url.split("://", 1)[1]] = {"url": url, "retrieved_at": now_iso(), "sha256": sha,
                                                          "bytes": size, **extra}


def httpd_conf(tmpl: str, version: str) -> str:
    lm = []
    for m in HTTPD_ENABLED:
        lm.append(f"LoadModule {m}_module modules/mod_{m}.so")
    for m in HTTPD_DISABLED:
        lm.append(f"#LoadModule {m}_module modules/mod_{m}.so")
    subs = {"@@ServerRoot@@": "/opt/httpd", "@@Port@@": "80", "@@SSLPort@@": "443", "@@LoadModule@@": "\n".join(lm),
            "@exp_htdocsdir@": "/opt/httpd/htdocs", "@exp_cgidir@": "/opt/httpd/cgi-bin",
            "@rel_logfiledir@": "logs", "@rel_sysconfdir@": "conf", "@rel_runtimedir@": "logs",
            "@exp_runtimedir@": "/opt/httpd/logs", "@exp_logfiledir@": "/opt/httpd/logs",
            "@exp_sysconfdir@": "/opt/httpd/conf", "@exp_errordir@": "/opt/httpd/error",
            "@exp_iconsdir@": "/opt/httpd/icons", "@exp_manualdir@": "/opt/httpd/manual",
            "@exp_libexecdir@": "/opt/httpd/modules", "@rel_libexecdir@": "modules",
            "@DEFAULT_PIDLOG@": "logs/httpd.pid"}
    for k, v in subs.items():
        tmpl = tmpl.replace(k, v)
    left = sorted(set(re.findall(r"@@?\w+@@?", tmpl)))
    assert not left, f"unsubstituted placeholders in httpd {version}: {left}"
    return tmpl


def fetch_one(item, man: VManifest) -> str:
    product, v = item
    dest = VX / product / v
    if (dest / ".done").exists():
        return f"{product} {v} cached"
    dest.mkdir(parents=True, exist_ok=True)
    if product == "tomcat":
        major = v.split(".")[0]
        url = f"https://archive.apache.org/dist/tomcat/tomcat-{major}/v{v}/bin/apache-tomcat-{v}.tar.gz"
        keep = {"RELEASE-NOTES", "RUNNING.txt", "NOTICE", "conf/server.xml", "conf/web.xml", "conf/context.xml",
                "conf/tomcat-users.xml", "conf/catalina.properties", "conf/logging.properties"}

        def want(name):
            rel = name.split("/", 1)[1] if "/" in name else ""
            return rel if rel in keep else None

        got = stream_tar(url, want, man, dest)
        assert "RELEASE-NOTES" in got and "conf/server.xml" in got, f"tomcat {v}: {sorted(got)}"
    elif product == "httpd":
        url = f"https://archive.apache.org/dist/httpd/httpd-{v}.tar.gz"
        keep = {"include/ap_release.h", "docs/conf/httpd.conf.in"}

        def want(name):
            rel = name.split("/", 1)[1] if "/" in name else ""
            return rel if rel in keep else None

        got = stream_tar(url, want, man, dest)
        assert set(got) == keep, f"httpd {v}: {sorted(got)}"
        (dest / "httpd.conf").write_text(httpd_conf((dest / "docs/conf/httpd.conf.in").read_text(), v))
    elif product == "roundcube":
        # the release tarball (the version string is stamped into iniset.php at packaging time; git tags of
        # maintenance branches still say e.g. '1.5-git')
        url = f"https://github.com/roundcube/roundcubemail/releases/download/{v}/roundcubemail-{v}.tar.gz"
        keep = {"program/include/iniset.php", "CHANGELOG.md", "CHANGELOG", "README.md", "config/defaults.inc.php"}

        def want(name):
            rel = name.split("/", 1)[1] if "/" in name else ""
            return rel if rel in keep else None

        got = stream_tar(url, want, man, dest)
        t = (dest / "program/include/iniset.php").read_text()
        assert f"define('RCMAIL_VERSION', '{v}')" in t, f"roundcube {v} iniset mismatch"
    elif product == "gitlab":
        url = f"https://gitlab.com/gitlab-org/gitlab/-/raw/v{v}-ee/VERSION"
        p, new = fetch_cached(url, dest / "VERSION", min_interval=0.2, throttle_key="gl")
        assert not p.read_bytes().startswith(b'{"_status"'), f"gitlab {v} VERSION missing"
        man.add_remote(url, hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_size)
    elif product == "jenkins":
        pass
    (dest / ".done").write_text(now_iso())
    return f"{product} {v} ok"


def main() -> None:
    spec = [tuple(x) for x in load_json(CUR / "spec_vendor_versions.json")]
    man = VManifest("vendor_files", "Vendor release files (Apache-2.0 Tomcat/httpd; GPL-3.0 Roundcube; MIT GitLab)")
    with ThreadPoolExecutor(6) as ex:
        for msg in ex.map(lambda it: fetch_one(it, man), spec):
            print(msg, flush=True)
    man.save()
    print(json.dumps({"n": len(spec)}))


if __name__ == "__main__":
    main()
