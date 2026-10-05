# DeepCTI v3 — data contract for D7 "DeepCTI-Live-X"

Extends `docs/DATA_CONTRACT.md` (D1). Everything not stated here is as in D1 (rootfs fixtures, real files,
real scanner runs, labels from authoritative structured sources, splits by CVE, sealed test labels).

## Why D7
D1 is Debian-only and largely solved by a tracker lookup; version evidence is always structured (dpkg).
D7 adds settings where (a) the authority is not a distro tracker, (b) version evidence is in heterogeneous or
unstructured places, (c) scanners are genuinely noisy, and (d) configuration preconditions are common.

## Ecosystems (field `ecosystem`)
| ecosystem | hosts | component identity | version evidence on the host | label authority |
|---|---|---|---|---|
| `deb-ubuntu` | ubuntu:22.04 (jammy), ubuntu:24.04 (noble) slim images | source package | dpkg status (+ changelog.Debian header) | Ubuntu CVE tracker (per-release status, fixed version) |
| `pypi` | Debian/Ubuntu base + an application venv under `opt/<app>/venv` | PyPI distribution name | `…/site-packages/<name>-<ver>.dist-info/METADATA` (`Name:`, `Version:`) | OSV PyPI ranges (GHSA/PYSEC) |
| `maven` | base + `opt/<app>/lib/*.jar` (real zip jars) | `groupId:artifactId` | jar file name, `META-INF/MANIFEST.MF` (`Implementation-Version`), `META-INF/maven/<g>/<a>/pom.properties` (`version=`) | OSV Maven ranges |
| `vendor` | base + vendor product under `opt/<product>` (e.g. Apache Tomcat, Jenkins, Elasticsearch, Confluence-like) | product name | ONLY unstructured text: `RELEASE-NOTES`, `VERSION.txt`, `README`, service banner (`host.json` services[*].banner); no package manager entry | vendor advisory ranges (from OSV/NVD CPE, curated and quoted) |

## Variants
D1 variants V1–V6 where meaningful, plus:
* **V7 vendored copy** — the vulnerable library is bundled inside another application (e.g. `log4j-core-2.14.1.jar` in
  `opt/app/lib`), not visible to the system package manager.
* **V8 unstructured-only** — version evidence exists only in free text / banners (ecosystem `vendor`).
* **V5 config-gated** — at least 30 cases over all ecosystems (e.g. Tomcat AJP connector (Ghostcat), Tomcat
  `readonly=false` PUT, Log4j `formatMsgNoLookups`/`log4j2.formatMsgNoLookups`, Spring4Shell preconditions,
  Werkzeug debugger, OpenSSH/nginx/samba/apache as in D1). Each with a quoted advisory statement.

## Files
```
data/d7/hosts/<host_id>/{rootfs/, host.json, scans/{trivy,grype,osv}.json}
data/d7/cases/{dev,calib,test}.jsonl      # test without label/atoms
data/d7/cve_meta.jsonl
data/d7/advisories/<CVE>.json            # {nvd, osv, kev, vendor, ubuntu|debian} plain text ≤ 6000 chars each
data/sealed/d7_test_labels.jsonl, data/sealed/D7_SHA256
config/config_preconditions_v3.yaml      # superset of D1's file; same schema + predicate kind `regex_present`
data/d7/BUILD_REPORT.md
```

## Case row (additions to D1)
```json
{"ecosystem": "maven", "component": "org.apache.logging.log4j:log4j-core",
 "install_paths": ["opt/app/lib/log4j-core-2.14.1.jar"],   // empty for deb
 "src_package": "<deb source package | component>", "binary_packages": [...],   // deb only; else []
 "variant": "V1..V8", ...}
```

## cve_meta row (additions)
```json
{"ecosystem": "...", "component": "...",
 "ranges": [{"introduced": "2.0-beta9", "fixed": "2.15.0"}, ...],      // ecosystem semantics; all branches
 "ubuntu": {"jammy": {"status": "released|needed|not-affected|DNE|needs-triage", "fixed_version": "..."}},
 "debian": {...}  // as D1 when the base is Debian
}
```

## Atom semantics
As D1, with `in_affected_range` / `fix_applied` computed by ecosystem-aware comparison (`univers` version
ranges: deb, pypi, maven, generic semver for vendor) of every installed instance; any instance in range →
`in_affected_range = true`. For `vendor`, `present` means the product directory with its files exists.

## host.json additions
`services[*].banner` (string printed by the running process, e.g. `Apache Tomcat/9.0.40`), `services[*].loaded_version`
(the version actually running; differs from on-disk only in drift cases), `apps`: list of {path, ecosystem, component}
for bookkeeping (NOT exposed to systems; the env discovers apps from files).
