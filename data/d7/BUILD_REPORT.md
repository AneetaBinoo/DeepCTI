FROZEN

# D7 (DeepCTI-Live-X) build report

**Status: FROZEN** (2026-10-05, ~16:55 UTC). After this point nothing under `data/d7/`, `data/sealed/d7_*` or
`config/config_preconditions_v3.yaml` is modified. Built on branch `v2-experiment` (not committed), data snapshot
2026-10-05, seed 20261005. Contract: `docs/DATA_CONTRACT_V3.md` on top of `docs/DATA_CONTRACT.md`.

## What was built

* **141 CVEs** in 4 ecosystems: deb-ubuntu 53, pypi 31, maven 29, vendor 28 (Tomcat 8, Apache httpd built
  from source 6, Jenkins 5, Roundcube 5, GitLab EE 4). 29 are in CISA KEV; 35 have a curated configuration
  precondition.
  * Split by CVE (seed 20261005, stratified by ecosystem × config-gated × temporal): dev 42 / calib 29 / test 70.
    The 23 CVEs that are also in D1 keep their D1 split, so D1 and D7 never put one CVE in test and in dev/calib.
  * Temporal hold-out (NVD `published` ≥ 2026-05-01): dev 18/42 (43%), calib 12/29 (41%), **test 30/70 (43%)**.
* **822 cases = 822 host fixtures** (one host per case): dev 243, calib 165, **test 414**.
  * By variant: V1 133, V2 207, V3 112, V4 115, **V5 41 (test 21)**, V6 126, V7 34, V8 54.
  * Base images: official `ubuntu:22.04@sha256:5ec03bb3…6401` (jammy) and `ubuntu:24.04@sha256:534baea6…eb55`
    (noble), linux/amd64, fetched via the Docker Registry v2 API (`data/base_images/{jammy,noble}/IMAGE.json`).
* Test labels sealed in `data/sealed/d7_test_labels.jsonl`, sha256
  `21857ab4dde6fe9a9afde19f23570f96935bc282ed4d0e10b429030685336c21` (also `data/sealed/D7_SHA256`).
  `data/d7/cases/test.jsonl` has no `label`/`atoms`. **No metric was computed on test.**
* Scanners ran on all 822 hosts, 0 failures: Trivy 0.75.0 (`rootfs`, DB 2026-10-05T01:10Z, Java DB
  2026-10-05T01:08Z), Grype 0.120.0 (`dir:`, DB v6.1.10 built 2026-10-04T08:11Z), OSV-Scanner 2.6.0 (`scan image
  --archive` of a single-layer docker-archive of the rootfs, **online** api.osv.dev, see deviations). Raw outputs:
  `data/d7/hosts/<id>/scans/{trivy,grype,osv}.json`; run metadata `data/d7/scanner_runs.json`.
* Advisory texts `data/d7/advisories/<CVE>.json` = {nvd, osv, kev, vendor, ubuntu}, each ≤ 6000 chars, rendered
  only from mirrors (`scripts/data/build_advisories_d7.py`).
* `data/d7/cve_meta.jsonl` (141 rows): D1 fields + `ecosystem`, `component`, `aliases`, `ranges` (all branches,
  ecosystem semantics; deb rows carry `release` per range), `ubuntu` {jammy,noble: status, fixed_version},
  `range_source`, `range_statement` (vendor), `alt_ranges` (other OSV records of the same CVE).

## Label authorities and data sources (all mirrored under `data/mirrors/<source>/2026-10-05/` with MANIFEST.json)

| ecosystem | version evidence on the host | label authority | comparator |
|---|---|---|---|
| deb-ubuntu | `var/lib/dpkg/status` + `usr/share/doc/<bin>/changelog.Debian` (real changelogs.ubuntu.com entries, 0 synthesized) | **Ubuntu CVE tracker JSON API** `https://ubuntu.com/security/cves/<CVE>.json` (`ubuntu_cve_tracker`) | dpkg |
| pypi | `opt/<app>/venv/lib/pythonX.Y/site-packages/<dist>.dist-info/METADATA` (fields from the PyPI JSON API of that release); V7: `pip/_vendor/vendor.txt` + package dir | OSV PyPI export (GHSA record primary; other records kept as `alt_ranges` and required to agree on every fixture version) | PEP 440 |
| maven | `opt/<app>/lib/<a>-<v>.jar` (valid zip: `META-INF/MANIFEST.MF` with Implementation-Version + `META-INF/maven/<g>/<a>/pom.properties` + pom.xml, no classes); V7: stored nested jar in a Spring Boot fat jar `BOOT-INF/lib/` | OSV Maven export (same rule as PyPI) | Maven ComparableVersion |
| vendor | only text: Tomcat `RELEASE-NOTES` + `conf/*.xml` from the official binary tarball; httpd `include/ap_release.h` (version split over three `#define`s) + `conf/httpd.conf` generated from the release's `httpd.conf.in`; Jenkins `JENKINS_HOME` files (`config.xml` `<version>`, `jenkins.install.InstallUtil.lastExecVersion`); Roundcube `program/include/iniset.php` + `CHANGELOG.md` from the release tarball; GitLab `embedded/service/gitlab-rails/VERSION` from the release tag; plus `services[*].banner` | curated `data/d7/curation/vendor_ranges.yaml` (vendor statement quoted in `range_statement`, cross-checked against NVD CPE) | semver-like |

* **Ubuntu data source check (2026-10-05).** The official Ubuntu CVE tracker is published at
  ubuntu.com/security/cves (JSON API, per-release `status` + fixed version in `description`); Canonical also
  publishes OSV records (`UBUNTU-CVE-*`, github.com/canonical/ubuntu-security-notices, imported by OSV.dev). The
  tracker JSON is the label authority; every released fixed version was cross-checked against the OSV Ubuntu
  export (`tools/cache/osv/osv-scalibr/Ubuntu/all.zip`): **0 mismatches**. Real vulnerable versions come from the
  Launchpad publication history (only versions published to -security/-updates plus the final release-pocket
  version; pre-release development uploads excluded); fixed versions are the current archive versions.
* All labels are computed by `scripts/data/label_d7.py` with the shared comparator
  `src/deepcti/core/versions.py::classify` (never string comparison) on the installed instances discovered in
  the fixture; `scripts/data/label_d7.py --check` recomputes all 822 cases: 0 mismatches.
* Every installed version is a real upstream version (validator `version.real`: PyPI releases, Maven Central
  metadata, Apache archive listings, Jenkins `jenkins-war` metadata, Roundcube/GitLab release tags, Launchpad).

## Natural scanner-vs-label disagreement (dev+calib only, 408 cases)

"Flagged" = the scanner reports the case CVE anywhere on the host (ID, alias or related ID). Compared with
`label.status == affected`.

| scanner | deb-ubuntu (n=137) | pypi (n=85) | maven (n=103) | vendor (n=83) |
|---|---|---|---|---|
| trivy | 10 (7.3%): FP 10 (V5 9, V4 1) | 6 (7.1%): FP 2 (V5), FN 4 (V7) | 5 (4.9%): FP 5 (V5) | 26 (31.3%): FN 26 (V8) |
| grype | 11 (8.0%): FP 11 (V5 9, V4 1, V3 1) | 6 (7.1%): FP 2 (V5), FN 4 (V7) | 5 (4.9%): FP 5 (V5) | 26 (31.3%): FN 26 (V8) |
| osv-scanner | 9 (6.6%): FP 9 (V5) | 6 (7.1%): FP 2 (V5), FN 4 (V7) | 5 (4.9%): FP 5 (V5) | 26 (31.3%): FN 26 (V8) |

Reading: on structured evidence (dpkg, dist-info, pom.properties — including jars nested in fat jars) all three
scanners match the authorities; they fail exactly where D7 was designed to differ: configuration-gated V5
(flagged although not exploitable), pip-vendored copies (V7, missed) and vendor products whose version exists
only in text/banners (V8, all missed by all scanners). Two Ubuntu backport/fixed hosts (V3/V4) are flagged by
Trivy/Grype against the tracker. OSV-Scanner shares its PyPI/Maven data with the label authority, so its
agreement there is partly by construction.

## Validation (`scripts/data/validate_d7.py`, exit code 0) — verbatim output

```
== validation checks
  advisory.exists                   141 checks     0 errors
  advisory.fields                   141 checks     0 errors
  advisory.len                      141 checks     0 errors
  advisory.nonempty                 141 checks     0 errors
  case.aliases                      822 checks     0 errors
  case.atoms                        822 checks     0 errors
  case.expected_by_variant          822 checks     0 errors
  case.fields                       822 checks     0 errors
  case.install_paths                529 checks     0 errors
  case.installed_version            822 checks     0 errors
  case.label_enum                   822 checks     0 errors
  case.label_from_atoms             822 checks     0 errors
  case.meta_flags                   822 checks     0 errors
  case.recompute                    822 checks     0 errors
  case.unique                       822 checks     0 errors
  case.variant                      822 checks     0 errors
  changelog                         497 checks     0 errors
  comparator.known_pairs             25 checks     0 errors
  dpkg.parse                        822 checks     0 errors
  files.apps                        441 checks     0 errors
  files.config                     1083 checks     0 errors
  files.install_paths               359 checks     0 errors
  host.apps                         441 checks     0 errors
  host.fields                       822 checks     0 errors
  host.services                     624 checks     0 errors
  jar.manifest                      685 checks     0 errors
  jar.nested_stored                  87 checks     0 errors
  jar.pom                           685 checks     0 errors
  jar.zip                           685 checks     0 errors
  meta.ecosystem                    141 checks     0 errors
  meta.fields                       141 checks     0 errors
  meta.precondition                 141 checks     0 errors
  meta.range_kinds                  266 checks     0 errors
  meta.temporal                     141 checks     0 errors
  meta.ubuntu                        53 checks     0 errors
  pypi.metadata                     621 checks     0 errors
  range.guard                       563 checks     0 errors
  req.ecosystems                      4 checks     0 errors
  req.n_cases                         1 checks     0 errors
  req.n_cves                          1 checks     0 errors
  req.temporal_test_share             1 checks     0 errors
  req.test_cases                      1 checks     0 errors
  req.v5_test                         1 checks     0 errors
  req.v5_total                        1 checks     0 errors
  scan.grype                        822 checks     0 errors
  scan.osv                          822 checks     0 errors
  scan.trivy                        822 checks     0 errors
  seal.hash                           1 checks     0 errors
  seal.ids                            1 checks     0 errors
  seal.no_labels                      1 checks     0 errors
  splits.disjoint                     1 checks     0 errors
  splits.meta                       141 checks     0 errors
  variant.absent                    259 checks     0 errors
  variant.decoy_not_affected         54 checks     0 errors
  variant.unstructured               54 checks     0 errors
  variant.v4_branch_fix              45 checks     0 errors
  variant.v5_file                    41 checks     0 errors
  variant.vendored                   34 checks     0 errors
  vendor.no_pkg_entry               111 checks     0 errors
  version.real                      563 checks     0 errors
TOTAL errors: 0

== known comparator limitations (not fatal; avoided by construction)
  vendor: compare(9.0.0.M1,9.0.0)=0, correct -1
  vendor: compare(9.0.0.M22,9.0.0.M3)=0, correct 1
  classify() ignores `last_affected` (only introduced/fixed); D7 ranges avoid it except log4j:log4j (last_affected = final release 1.2.17), guarded by range.guard above

== warnings (0)

== cases per split x ecosystem x variant
  split  ecosystem     V1   V2   V3   V4   V5   V6   V7   V8  total
  dev    deb-ubuntu    12   25   12   17    5   12    0    0     83
  dev    pypi           9   18    9    1    1    8    3    0     49
  dev    maven          9   18    8    6    3    8    9    0     61
  dev    vendor         8    0    8    8    2    8    0   16     50
  calib  deb-ubuntu     8   15    6   13    4    8    0    0     54
  calib  pypi           7   14    7    0    1    6    1    0     36
  calib  maven          6   12    6    4    2    6    6    0     42
  calib  vendor         6    0    6    3    2    6    0   10     33
  test   deb-ubuntu    25   47    9   40   11   24    0    0    156
  test   pypi          15   30   15    4    1   12    1    0     78
  test   maven         14   28   12    8    6   14   14    0     96
  test   vendor        14    0   14   11    3   14    0   28     84
  totals: dev=243, calib=165, test=414, all=822

== CVEs per split (temporal hold-out = NVD published >= 2026-05-01)
  dev    cves= 42 temporal= 18 (43%) kev=7 config_gated=10 by_eco={'deb-ubuntu': 16, 'maven': 9, 'pypi': 9, 'vendor': 8}
  calib  cves= 29 temporal= 12 (41%) kev=7 config_gated=8 by_eco={'pypi': 7, 'maven': 6, 'deb-ubuntu': 10, 'vendor': 6}
  test   cves= 70 temporal= 30 (43%) kev=15 config_gated=17 by_eco={'deb-ubuntu': 27, 'vendor': 14, 'maven': 14, 'pypi': 15}
  V5 cases: {'dev': 11, 'calib': 9, 'test': 21} total=41

== natural scanner-vs-label disagreement (dev+calib only; scanner flags CVE anywhere on host vs label == affected)
  grype  deb-ubuntu  n= 137 disagree=  11 (8.0%) flagged_not_affected=11 missed_affected=0 by_variant={'V5': 9, 'V4': 1, 'V3': 1}
  grype  maven       n= 103 disagree=   5 (4.9%) flagged_not_affected=5 missed_affected=0 by_variant={'V5': 5}
  grype  pypi        n=  85 disagree=   6 (7.1%) flagged_not_affected=2 missed_affected=4 by_variant={'V5': 2, 'V7': 4}
  grype  vendor      n=  83 disagree=  26 (31.3%) flagged_not_affected=0 missed_affected=26 by_variant={'V8': 26}
  osv    deb-ubuntu  n= 137 disagree=   9 (6.6%) flagged_not_affected=9 missed_affected=0 by_variant={'V5': 9}
  osv    maven       n= 103 disagree=   5 (4.9%) flagged_not_affected=5 missed_affected=0 by_variant={'V5': 5}
  osv    pypi        n=  85 disagree=   6 (7.1%) flagged_not_affected=2 missed_affected=4 by_variant={'V5': 2, 'V7': 4}
  osv    vendor      n=  83 disagree=  26 (31.3%) flagged_not_affected=0 missed_affected=26 by_variant={'V8': 26}
  trivy  deb-ubuntu  n= 137 disagree=  10 (7.3%) flagged_not_affected=10 missed_affected=0 by_variant={'V5': 9, 'V4': 1}
  trivy  maven       n= 103 disagree=   5 (4.9%) flagged_not_affected=5 missed_affected=0 by_variant={'V5': 5}
  trivy  pypi        n=  85 disagree=   6 (7.1%) flagged_not_affected=2 missed_affected=4 by_variant={'V5': 2, 'V7': 4}
  trivy  vendor      n=  83 disagree=  26 (31.3%) flagged_not_affected=0 missed_affected=26 by_variant={'V8': 26}
```

The validator checks: contract field lists and order (cases, cve_meta, host.json incl. `services[*].banner` /
`loaded_version` and `apps[*].version`), enums, label = decision table(atoms), full recomputation of every case
from the fixture (test against the sealed file), comparator sanity on known pairs per ecosystem, a guard that
`classify` equals an independent implementation (incl. `last_affected`) on every installed instance, real
upstream versions, variant semantics (V1/V6 absent, V7 only vendored/nested instances, V8 only vendor, V4 below
the highest fix, V5 precondition file present), referenced files exist (install paths incl. `jar!/nested`,
service config files, apps), every jar (and nested jar) is a valid zip with MANIFEST.MF + pom.properties and
nested jars are stored, every dist-info METADATA has Name/Version, dpkg status parses, changelog headers match
the installed version, scanners outputs parse, splits disjoint by CVE and consistent with cve_meta, the seal,
advisory files, decoys (V6) never appear in the CVE's OSV affected packages, and the global requirements
(≥120 CVEs, 500–1000 cases, test ≥ 400, V5 ≥ 30 / ≥ 10 in test, temporal share of test CVEs ≥ 25%).

## Variants as built

| variant | deb-ubuntu | pypi | maven | vendor |
|---|---|---|---|---|
| V1 absent | source package absent | app venv without the distribution | app `lib/` without the jar | product directory absent |
| V2 vulnerable | shipped version < Ubuntu fix (or current if `needed`) | release in range (newest 3 below the top fix) | same | — (V8 plays this role) |
| V3 fixed | current archive version ≥ fix, upstream outside NVD range | the top fix release | same | same |
| V4 backport / branch fix | current version ≥ fix with upstream inside the NVD range | **fix on a lower maintenance branch** (≥ that branch's fix, < highest fix: a single-threshold compare says vulnerable) | same | same (incl. Jenkins LTS vs weekly) |
| V5 config-gated | V2 version + safe configuration | same | same | same |
| V6 decoy | other source package with overlapping name/vendor | independent PyPI project (e.g. `types-urllib3`, `jwt` for PyJWT, `multipart`) | other artifact (e.g. `log4j-api`, `log4j-over-slf4j`, Struts 1 `struts-core`) | other product (httpd↔Tomcat, Jenkins agent, GitLab Runner, RCMCardDAV) |
| V7 vendored | — | copy inside `pip/_vendor/` of a real pip release (urllib3/requests/idna) | stored nested jar in a Spring Boot fat jar | — |
| V8 unstructured | — | — | — | vulnerable product, version only in text files / banner |

Cases tagged `-b2` are a second vulnerable instance per CVE (V2/V8): the newest release of another vulnerable
branch, or an older release of the same branch.

## Configuration preconditions (`config/config_preconditions_v3.yaml`)

D1's 14 entries copied unchanged (verified equal), plus 27 D7 entries (6 deb-ubuntu, 11 maven, 3 pypi,
7 vendor) with verbatim quotes from the mirrored advisory pages (`data/mirrors/advisory_pages/2026-10-05/`).
D7 CVEs with preconditions: 35 (8 of them D1 entries reused on Ubuntu: CVE-2024-6387, -2025-26465, -2023-25690,
-2023-2911, -2023-42115/6/7, -2023-4091). Schema additions (optional): `ecosystem`, `component`,
`applies_to_versions` (e.g. Log4Shell's `formatMsgNoLookups` only exists in 2.10–2.14.1), predicate kind
`regex_present` (`pattern`; evaluated after removing XML comments and `#`/`;` comment lines).

## CMDB and host records

* 159/822 hosts (19.3%) carry a stale CMDB record (seeded, as in D1: the version of the opposite state).
* Non-distro software in the CMDB: drawn for 71% of the 529 pypi/maven/vendor hosts (seeded); 321 of them
  (61%) actually list an application entry (V1 hosts have nothing to list).
* `services[*]` carry `banner` (real formats, e.g. `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7`,
  `Apache/2.4.52 (Ubuntu)`, `Apache Tomcat/9.0.30`, `Apache/2.4.49 (Unix)`, `X-Jenkins: 2.441`,
  `Werkzeug/3.0.1 Python/3.10.12`) and `loaded_version` (= on-disk version; D7 has no drift cases).
* `apps` = [{path, ecosystem, component, version, …}] bookkeeping with the TRUE version (not for systems).
* `data/d7/hosts_meta.jsonl` is build-side truth (stale flags, CMDB versions, decoys, pip versions).

## Deviations from the contract / plan

1. **OSV-Scanner online.** OSV-Scanner 2.6.0 offline does not match Ubuntu packages (extractor ecosystem
   `Ubuntu:22.04` vs. export `Ubuntu:22.04:LTS`) and silently reported nothing for OS packages. All 822 hosts were
   therefore scanned with OSV-Scanner against the online api.osv.dev database (same day). Trivy and Grype ran
   offline as in D1. Trivy fetched its Java DB once (2026-10-05T15:12Z) on the first jar scan.
2. **No `-slim` Ubuntu images exist**; the official `ubuntu:22.04/24.04` images (already minimal) are used.
   All pypi/maven/vendor hosts also use the Ubuntu bases (python 3.10 on jammy, 3.12 on noble).
3. **V4 outside deb** = maintenance-branch fix (see table); **V8** replaces V2 for vendor; extra `-b2` vulnerable
   instances; V7 is pip-vendored (pypi) / nested fat-jar (maven) only. Application venvs are created
   `--without-pip` except V7 hosts (otherwise pip's vendored urllib3/requests/idna would be present everywhere).
4. **Splits**: seeded stratified by CVE, but the 23 CVEs already in D1 keep their D1 split (dev 42 / calib 29 /
   test 70 overall).
5. **Vendor ranges curated**: Jenkins LTS and weekly lines get separate ranges ([0, LTS fix) and
   [first weekly after the LTS baseline, weekly fix)); Tomcat 8.5 EOL (no fix) folded into the 9.0 range for
   CVE-2025-24813; CVE-2020-9484 uses the conservative union of the Tomcat page (fixed 9.0.35) and NVD/CVE-2021-25329
   ("still vulnerable", fixed 9.0.43); Roundcube CVE-2026-62643/75007 follow the description ("before 1.6.17")
   rather than NVD's CPE start 1.6.0.
6. **Dropped**: CVE-2022-22947 (OSV names the POM artifact `spring-cloud-gateway`, which never exists as a jar).
   Recent-pick CVE-2026-42198 turned out to be NVD-published 2026-04-29 (kept, not temporal).
7. **Changelogs**: real Ubuntu changelog blocks for all 497 deb binaries (python-debian prints harmless
   "Unexpected line" parser warnings for some libwebp entries).

## Known weaknesses

* **Shared comparator limits** (reported to the lead, not worked around): `classify` ignores `last_affected`
  (treats it as unbounded); `vendor` semver coerces Tomcat milestones (`9.0.0.M1 == 9.0.0 == 9.0.0.M22`). D7
  avoids both by construction (no milestone fixture versions; the only `last_affected` range is log4j:log4j
  1.2.17 = final release), and the validator's `range.guard` proves agreement on every instance.
* **Log4Shell V5** relies on the original (2021-12-11, archived) Apache mitigation `log4j2.formatMsgNoLookups=true`
  for 2.10–2.14.1, which Apache later called insufficient (other lookup paths = CVE-2021-45046). The V5 fixtures
  keep the default PatternLayout; still, a reviewer may contest this label (1 case).
* Several preconditions encode a necessary condition, not the full exploit chain (CVE-2021-40438 mod_proxy
  loaded, CVE-2023-38408 agent forwarding, CVE-2018-11776 alwaysSelectFullNamespace, CVE-2022-22965 JDK 9+ only,
  CVE-2020-9484 FileStore). Each quote is in the YAML.
* pip-vendored V7 copies are labelled `affected` (the vulnerable code is present and used by pip), which some
  vendors would call "not reachable from the application".
* Fixtures are metadata-level: jars have no classes, dist-info packages have a stub `__init__.py`, python
  version compatibility of old releases (e.g. Werkzeug 0.11.15 in a 3.10 venv) is not enforced, Jenkins/GitLab
  manifest files are generated in the product's format rather than copied from a package.
* OSV-Scanner (online) and the pypi/maven labels share the OSV data source; agreement there is not independent
  evidence. pypi V5 is thin (3 cases); vendor V1 hosts are empty bases.
* Python-server banners use a fixed interpreter string (`Werkzeug/<v> Python/3.10.12`, `Python/3.10 aiohttp/<v>`)
  also on noble hosts, whose venv is python 3.12 (cosmetic inconsistency; the component version in the banner is
  correct).
* deb-ubuntu V3 is rare (Ubuntu backports keep upstream versions, so most fixed hosts are V4).

## Reproduce

```
.venv/bin/python scripts/data/mirror_d7.py base|ubuntu_archive|osv_zips|launchpad|...   # mirrors
.venv/bin/python scripts/data/select_d7.py candidates && .venv/bin/python scripts/data/select_d7.py finalize
.venv/bin/python scripts/data/build_d7.py plan          # -> curation/plan.json + fetch specs
.venv/bin/python scripts/data/mirror_d7.py ubuntu_changelogs|pypi --spec data/d7/curation/spec_*.json
.venv/bin/python scripts/data/fetch_vendor_d7.py        # vendor tarballs/tags -> data/cache/vendorx/
.venv/bin/python scripts/data/build_d7.py build && .venv/bin/python scripts/data/build_advisories_d7.py
.venv/bin/python scripts/data/run_scanners_d7.py --osv-online && .venv/bin/python scripts/data/run_scanners_d7.py
.venv/bin/python scripts/data/validate_d7.py
```
