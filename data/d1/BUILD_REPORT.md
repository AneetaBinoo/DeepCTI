# D1 (DeepCTI-Live) build report

Built on 2026-10-05 by `scripts/data/` on branch v2-experiment, data snapshot 2026-10-05, seed 20261005.
**Status: FROZEN** (05:35 UTC). After this point nothing under data/d1, data/sealed or config/ is modified.

## What was built

* **192 CVEs** across 32 Debian source packages and 10 families. Of these, 22 are in KEV and 14 have a
  curated configuration precondition.
  * By split (CVE count): dev 58, calib 38, test 96.
  * Temporal hold-out CVEs (NVD `published` ≥ **2026-05-01**, following the lead's update): dev 27/58 (47%),
    calib 15/38 (39%), **test 46/96 (48%)**. Test cases from those CVEs: 217/453.
* **906 cases** and the same number of host fixtures (one host per case): dev 282, calib 171, test 453.
  * By variant: V1 173, V2 280, V3 188, V4 92, V5 7, V6 166.
  * Releases: bookworm (Debian 12) and trixie (Debian 13). See the deviations section for why bullseye is missing.
* Test labels are sealed in `data/sealed/test_labels.jsonl`.
  * sha256 `2f6043bb0f08362fdfe12d1bde09d121fdccb86deceb74c205ad39abb31ca2be` (also in `data/sealed/SHA256`).
  * `cases/test.jsonl` has no `label` or `atoms` fields.
  * No metric was computed on test.
* Scanners ran offline on all 906 hosts with 0 failures: Trivy 0.75.0, Grype 0.120.0, OSV-Scanner 2.6.0.
  Outputs are in `data/d1/hosts/<id>/scans/{trivy,grype,osv}.json`. Versions and DB metadata are in
  `data/d1/scanner_runs.json` and `docs/VERIFICATION_LOG.md` ("## Data sources").
* **D6:** 3000 tuples (dev 899 / calib 597 / test 1504) in `data/d6/`.
  * Labels: affected_open 1000, fixed_in_version 1200, not_affected 800.
  * Split by CVE with the same seed and proportions.
  * D1 test CVEs are excluded from D6 entirely. D1 dev/calib CVEs never go to D6 test.
* Advisory texts are in `data/d1/advisories/<CVE>.json`: {nvd, osv, kev, debian} plain text, each ≤ 6000 chars,
  rendered only from the mirrors.

## Natural scanner-vs-tracker disagreement (dev+calib only, 453 cases)

A case counts as "flagged" when the scanner reports the case CVE anywhere on the host. The comparison is
flagged vs `label.status == affected`.

| scanner | disagree | flagged but not affected | missed affected | by variant |
|---|---|---|---|---|
| trivy | 6 (1.3%) | 6 | 0 | V5: 6 |
| grype | 6 (1.3%) | 6 | 0 | V5: 6 |
| osv-scanner | 6 (1.3%) | 6 | 0 | V5: 6 |

All three scanners match on Debian source package and version, using Debian tracker / OSV `Debian:N` data
of the same day. Their verdicts therefore agree with the tracker-derived labels everywhere except the
configuration-gated V5 cases. Name-overlap decoys (V6) and upstream-in-range backports (V4) did **not** fool
them. In other words, the scanner baseline is strong on version questions. The remaining hard parts are
configuration, CMDB staleness and the backport reasoning an LLM must do without a version-aware scanner.

## Validation (`scripts/data/validate_d1.py`, exit code 0)

```
== validation checks
  advisory                        384 checks     0 errors
  case.atoms                      906 checks     0 errors
  case.base_image                 906 checks     0 errors
  case.fields                     906 checks     0 errors
  case.id                         906 checks     0 errors
  case.installed_version          906 checks     0 errors
  case.label_enum                 906 checks     0 errors
  case.label_from_atoms           906 checks     0 errors
  case.meta_flags                 906 checks     0 errors
  case.recompute                  906 checks     0 errors
  case.release                    906 checks     0 errors
  case.req_config                 906 checks     0 errors
  case.unique                     906 checks     0 errors
  case.variant                    906 checks     0 errors
  changelog                      1347 checks     0 errors
  dpkg.fields                   76740 checks     0 errors
  dpkg.unique                     906 checks     0 errors
  dpkg.version                  76740 checks     0 errors
  host.fields                     906 checks     0 errors
  host.services                  2023 checks     0 errors
  meta.debian                     362 checks     0 errors
  meta.fields                     192 checks     0 errors
  meta.split                      192 checks     0 errors
  scan.grype                      906 checks     0 errors
  scan.osv                        906 checks     0 errors
  scan.trivy                      906 checks     0 errors
  seal.hash                         1 checks     0 errors
  seal.ids                          1 checks     0 errors
  seal.no_labels                    1 checks     0 errors
  splits.disjoint                   3 checks     0 errors
  splits.meta                     906 checks     0 errors
  variant.absent                  339 checks     0 errors
  variant.fixed                   280 checks     0 errors
  variant.vulnerable              287 checks     0 errors
TOTAL errors: 0

== cases per split x variant
  split     V1    V2    V3    V4    V5    V6  total
  dev       56    88    60    20     3    55    282
  calib     33    52    33    20     3    30    171
  test      84   140    95    52     1    81    453

== cases per split x family x release
  family          dev:bw/tx  calib:bw/tx  test:bw/tx
  compression         12/10        5/5        10/10 
  crypto_tls          21/14        9/12       38/29 
  dns                  9/10        9/8        13/14 
  file_sharing         9/7         4/5        14/14 
  interpreter         12/16       11/8        24/28 
  library             42/36       22/19       66/64 
  mail                11/9         6/4        16/14 
  privesc              6/6         7/7        14/14 
  ssh                 11/9         6/4        10/10 
  web_server          16/16       10/10       26/25 

== CVEs per split (temporal hold-out = published >= 2026-05-01, KEV)
  dev    cves= 58 temporal_holdout= 27 (47%) kev=5 config_gated=5
  calib  cves= 38 temporal_holdout= 15 (39%) kev=8 config_gated=3
  test   cves= 96 temporal_holdout= 46 (48%) kev=9 config_gated=6

== natural scanner-vs-tracker disagreement (dev+calib only; scanner flags CVE on host vs label)
  trivy  n=453 disagree=6 (1.3%) flagged_not_affected=6 missed_affected=0 by_variant={'V5': 6}
  grype  n=453 disagree=6 (1.3%) flagged_not_affected=6 missed_affected=0 by_variant={'V5': 6}
  osv    n=453 disagree=6 (1.3%) flagged_not_affected=6 missed_affected=0 by_variant={'V5': 6}
```

`scripts/data/validate_d1.py` checks the following:

* Field lists and order against the contract, for case rows, cve_meta and host.json.
* Enums for variant, status and justification.
* Labels against the decision table applied to the atoms.
* A full recomputation of installed version, atoms and label from the fixture (dpkg status read with
  python-debian, tracker snapshot, config predicate). For test cases this compares against the sealed file.
* Variant semantics:
  * V1/V6: the source package is absent.
  * V2/V5: installed version < fixed version.
  * V3/V4: installed version ≥ fixed version.
* dpkg status files: every stanza parses with python-debian and has Package, Status, Priority, Section,
  Installed-Size, Maintainer, Architecture, Version and Description. Every version parses. No duplicate packages.
* The first line of `usr/share/doc/<bin>/changelog.Debian` matches the installed version.
* Every installed daemon has a `services` entry with {unit, active, package, config_files}.
* All three scanner JSON files exist and parse.
* Splits are disjoint by CVE and match cve_meta.
* The seal: hash, id coverage, and no labels in test.jsonl.
* An advisory file exists for every CVE.

### Cases per split × family × release × variant

| split | family | release | V1 | V2 | V3 | V4 | V5 | V6 | total |
|---|---|---|---|---|---|---|---|---|---|
| dev | compression | bookworm | 0 | 4 | 2 | 2 | 0 | 4 | 12 |
| dev | compression | trixie | 4 | 4 | 0 | 2 | 0 | 0 | 10 |
| dev | crypto_tls | bookworm | 5 | 6 | 6 | 0 | 0 | 4 | 21 |
| dev | crypto_tls | trixie | 1 | 6 | 5 | 1 | 0 | 1 | 14 |
| dev | dns | bookworm | 3 | 2 | 3 | 0 | 0 | 1 | 9 |
| dev | dns | trixie | 1 | 2 | 4 | 0 | 0 | 3 | 10 |
| dev | file_sharing | bookworm | 1 | 2 | 2 | 1 | 1 | 2 | 9 |
| dev | file_sharing | trixie | 2 | 1 | 3 | 0 | 0 | 1 | 7 |
| dev | interpreter | bookworm | 3 | 4 | 2 | 0 | 0 | 3 | 12 |
| dev | interpreter | trixie | 4 | 5 | 3 | 0 | 0 | 4 | 16 |
| dev | library | bookworm | 10 | 16 | 3 | 5 | 0 | 8 | 42 |
| dev | library | trixie | 5 | 13 | 7 | 4 | 0 | 7 | 36 |
| dev | mail | bookworm | 2 | 2 | 3 | 1 | 1 | 2 | 11 |
| dev | mail | trixie | 2 | 1 | 3 | 1 | 0 | 2 | 9 |
| dev | privesc | bookworm | 3 | 2 | 1 | 0 | 0 | 0 | 6 |
| dev | privesc | trixie | 0 | 2 | 1 | 0 | 0 | 3 | 6 |
| dev | ssh | bookworm | 1 | 4 | 0 | 2 | 1 | 3 | 11 |
| dev | ssh | trixie | 3 | 3 | 1 | 1 | 0 | 1 | 9 |
| dev | web_server | bookworm | 1 | 5 | 5 | 0 | 0 | 5 | 16 |
| dev | web_server | trixie | 5 | 4 | 6 | 0 | 0 | 1 | 16 |
| calib | compression | bookworm | 0 | 2 | 0 | 2 | 0 | 1 | 5 |
| calib | compression | trixie | 1 | 2 | 0 | 2 | 0 | 0 | 5 |
| calib | crypto_tls | bookworm | 1 | 4 | 1 | 3 | 0 | 0 | 9 |
| calib | crypto_tls | trixie | 3 | 4 | 1 | 3 | 0 | 1 | 12 |
| calib | dns | bookworm | 0 | 3 | 2 | 0 | 1 | 3 | 9 |
| calib | dns | trixie | 3 | 2 | 3 | 0 | 0 | 0 | 8 |
| calib | file_sharing | bookworm | 1 | 1 | 1 | 0 | 0 | 1 | 4 |
| calib | file_sharing | trixie | 1 | 1 | 2 | 0 | 0 | 1 | 5 |
| calib | interpreter | bookworm | 3 | 3 | 1 | 1 | 0 | 3 | 11 |
| calib | interpreter | trixie | 2 | 2 | 2 | 0 | 0 | 2 | 8 |
| calib | library | bookworm | 4 | 10 | 1 | 3 | 0 | 4 | 22 |
| calib | library | trixie | 3 | 6 | 5 | 2 | 0 | 3 | 19 |
| calib | mail | bookworm | 1 | 1 | 1 | 1 | 1 | 1 | 6 |
| calib | mail | trixie | 1 | 0 | 2 | 0 | 0 | 1 | 4 |
| calib | privesc | bookworm | 1 | 2 | 1 | 1 | 0 | 2 | 7 |
| calib | privesc | trixie | 2 | 2 | 1 | 1 | 0 | 1 | 7 |
| calib | ssh | bookworm | 2 | 2 | 0 | 1 | 1 | 0 | 6 |
| calib | ssh | trixie | 0 | 1 | 1 | 0 | 0 | 2 | 4 |
| calib | web_server | bookworm | 1 | 2 | 4 | 0 | 0 | 3 | 10 |
| calib | web_server | trixie | 3 | 2 | 4 | 0 | 0 | 1 | 10 |
| test | compression | bookworm | 0 | 6 | 1 | 1 | 0 | 2 | 10 |
| test | compression | trixie | 2 | 5 | 2 | 1 | 0 | 0 | 10 |
| test | crypto_tls | bookworm | 7 | 11 | 11 | 1 | 0 | 8 | 38 |
| test | crypto_tls | trixie | 5 | 11 | 11 | 1 | 0 | 1 | 29 |
| test | dns | bookworm | 3 | 4 | 4 | 0 | 0 | 2 | 13 |
| test | dns | trixie | 2 | 4 | 5 | 0 | 0 | 3 | 14 |
| test | file_sharing | bookworm | 2 | 4 | 4 | 1 | 0 | 3 | 14 |
| test | file_sharing | trixie | 3 | 4 | 5 | 0 | 0 | 2 | 14 |
| test | interpreter | bookworm | 5 | 10 | 0 | 4 | 0 | 5 | 24 |
| test | interpreter | trixie | 5 | 8 | 6 | 4 | 0 | 5 | 28 |
| test | library | bookworm | 13 | 25 | 3 | 14 | 0 | 11 | 66 |
| test | library | trixie | 10 | 19 | 11 | 12 | 0 | 12 | 64 |
| test | mail | bookworm | 1 | 4 | 3 | 2 | 1 | 5 | 16 |
| test | mail | trixie | 5 | 2 | 5 | 1 | 0 | 1 | 14 |
| test | privesc | bookworm | 2 | 4 | 2 | 1 | 0 | 5 | 14 |
| test | privesc | trixie | 5 | 2 | 2 | 3 | 0 | 2 | 14 |
| test | ssh | bookworm | 1 | 3 | 1 | 2 | 0 | 3 | 10 |
| test | ssh | trixie | 3 | 3 | 1 | 2 | 0 | 1 | 10 |
| test | web_server | bookworm | 7 | 6 | 9 | 1 | 0 | 3 | 26 |
| test | web_server | trixie | 3 | 5 | 9 | 1 | 0 | 7 | 25 |

## Pipeline (all steps resumable from cache)

| step | script | output |
|---|---|---|
| mirrors | `mirror_sources.py {global,nvd,osv,snapshot,debs,changelogs}` | `data/mirrors/<src>/2026-10-05/` (+MANIFEST.json) |
| base images | `fetch_base_images.py` | `data/base_images/<rel>/{rootfs,IMAGE.json}`, `data/mirrors/docker_hub/` |
| CVE selection | `select_cves.py` (`--extend-from`, `--refresh-only`) | `data/d1/selected_cves.json` (frozen) |
| fixtures, cases, seal | `build_d1.py` (uses `label_live.py`) | hosts, cases, cve_meta, sealed labels |
| advisories | `build_advisories.py` | `data/d1/advisories/` |
| scanners | `run_scanners.py` | `hosts/*/scans/`, `data/d1/scanner_runs.json` |
| D6 | `build_d6.py` | `data/d6/` |
| validation | `validate_d1.py`; `label_live.py --check` | stdout (pasted above) |

## Decisions and deviations from the contract / brief

1. **No bullseye cases.** The tracker JSON of 2026-10-05 no longer contains bullseye (it carries only
   bookworm/trixie/forky/sid). Labels must come from the tracker, so D1 uses bookworm and trixie only. The
   bullseye-slim image was still fetched and its digest recorded.
2. **Temporal hold-out cutoff is 2026-05-01**, per the lead's update, not 2026-01-01. Dates come from NVD
   `published`, which was mirrored for all 192 CVEs. Selection favoured recent CVEs: about 60% of the
   non-KEV picks per package were published on/after the cutoff, using the OSV publication date as a
   proxy before NVD was mirrored.
3. **Selection is frozen and was extended once.**
   * The initial batch had 106 CVEs (498 cases).
   * It was extended by 86 CVEs (`batch: extension-1`, with per-package caps ×1.7).
   * Existing CVE→split assignments were never changed. New CVEs were split with the same seeded rule
     (stratified by family × temporal, sha256(seed|cve) order), applied to the new CVEs only.
   * Three rows of the initial selection had the same CVE under two source packages (python3.11/3.13,
     ruby3.1/3.3, php8.2/8.4). Only the first source package is kept.
   * `select_cves.py` now never selects a CVE twice.
   * `--refresh-only` refreshes publication dates and temporal flags only; it never changes splits.
4. **V2 (vulnerable) versions** have to be real and plausible *for that release*.
   * When the tracker fix carries an in-release marker (`+deb12uN`/`~deb12uN`, `+deb13uN`/`~deb13uN`), V2 is
     the highest snapshot.debian.org version below the fix that carries the same release marker or equals the
     pre-update base version.
   * When the tracker status is `open`, V2 is the current archive version (tracker `repositories`).
   * CVEs fixed before the release shipped (most older KEV CVEs) get no V2 in that release. They get only
     V1/V3/V4/V6.
5. **V3 vs V4** use the current archive version of the release, which is ≥ the fixed version.
   * Its normalized upstream part is compared, with python-debian ordering, against the NVD CPE ranges of the
     matching product (`nvd_ranges`).
   * Inside the range gives V4 (backport); otherwise V3.
   * Many 2026 CVEs have no NVD CPE configuration yet. Those default to V3, so the V4 count is conservative.
6. **V5 is limited to 7 cases (1 in test).** V5 needs a curated precondition *and* an in-release V2. Most of
   the curated, verified config-gated CVEs were fixed in Debian before bookworm/trixie were released. For
   those (CVE-2021-23017, -44142, -44224, -41617, CVE-2023-25690, CVE-2019-18634) `req_config` is true, but
   the cases are fixed/absent.
7. **Config predicates** (`config/config_preconditions.yaml`, 14 entries) follow the lead's machine-readable
   schema: service, file, key, predicate kind/value, safe_setting, advisory_url, quote. Every quote was
   fetched from the cited advisory. The YAML header documents the evaluation semantics.
   * For every host of a gated CVE, the fixture writes the key explicitly: the vulnerable setting for
     V2/V3/V4 (the feature is in use; on V3/V4 it is patched) and the safe setting for V5.
   * Two predicates are narrower than the advisory: samba fruit uses `value_equals` on the exact `vfs objects`
     value, and apache CVE-2023-25690 uses `module_enabled proxy.load`. Neither ever decides a label here,
     because both CVEs have only fixed/absent cases.
8. **`vuln_config_enabled` for non-gated CVEs** is `true` whenever the component is present (the vulnerable
   code is reachable in the default configuration) and `false` when it is absent.
9. **cve_meta `config_precondition`** has the contract keys {file, key, vulnerable_when, safe_value, source}
   plus `service` and `predicate`. These are additive.
10. **host.json** has the contract fields plus `processes` (the simulated process table).
    * `services` maps each installed daemon to {unit, active, package, config_files}.
    * Library-only hosts have `services: {}`.
    * Truth about CMDB perturbations is kept out of host.json, in `data/d1/hosts_meta.jsonl` (see 11).
11. **CMDB staleness** (seeded, per host): 198/906 hosts (21.9%) have `cmdb_stale: true`. Their CMDB software
    list comes from an earlier or alternative state of the same host:
    * V2/V5: the release's fixed (V3/V4) version.
    * V3/V4: the release's V2 version, or an empty list if none exists.
    * V1/V6: the source package's binaries at the current archive version (the package was later removed).

    `last_sync` of stale records is 2026-01…08. Non-stale records sync in 2026-09.
    `data/d1/hosts_meta.jsonl` records `cmdb_version` and `true_installed_version` for each host.
12. **Change tickets and rollback** are seeded: 442/906 hosts have a `CHG-2026xxxxx` ticket
    (`approved` with p=0.75, `window_open` with p=0.5), and 459/906 have `rollback_available: true`.
13. **dpkg status** starts from the base image's real status.
    * Base-image binaries of the target source (for example libc6, libssl3t64, liblzma5, perl-base) are moved
      to the target version. Exact `(= old)` pins between sibling binaries are rewritten.
    * Injected stanzas come from the real Packages entries of the release: Priority, Section, Installed-Size,
      Maintainer, Architecture, Multi-Arch, Description and Homepage, plus `Source:` (with `(version)` when it
      differs from the binary version).
    * **Relationship fields (Depends, Breaks, …) are dropped from injected stanzas.** They would otherwise
      reference archive-current versions and packages that are not in the fixture.
    * Package dependencies are *not* installed. A fixture contains the base image plus the target package's
      main binaries (and the decoy for V6).
14. **changelog.Debian** (lead request) is written for every installed binary of the case's source package,
    and for the decoy binary on V6 hosts.
    * The header, 1–3 change lines, maintainer and date come from the real Debian changelog
      (metadata.ftp-master, mirrored).
    * For 111 hosts the exact version was not in the newest available changelog (usually a security-only
      version). Those get a synthesized entry: the real header format `src (ver) rel-security; urgency=medium`,
      `* Security update.`, the Packages Maintainer, and the date of the preceding real entry. These hosts are
      marked `changelog_synthesized` in hosts_meta.
    * For binNMU decoys the source-version header is used.
15. **Default configuration files** are the real Debian conffiles from the current .deb of the release, for
    openssh, nginx, samba, apache2 (with default mods/conf/sites-enabled symlinks), exim4 (split config), bind9,
    sudo and postfix. `etc/hostname` is set per host.
16. **OSV-Scanner** runs in `scan image --archive` mode on a docker-archive tarball of each rootfs. A bare
    dpkg-status lockfile loses the Debian release (see VERIFICATION_LOG).
17. **`installed_version`** is the *source* version of the installed binaries of `src_package`; binary
    versions equal it except for archive binNMUs, which are shown via `Source: src (ver)`.
    `label_provenance` = `debian-tracker@2026-10-05 + dpkg --compare-versions (python-debian)`.
18. **D6** labels come straight from the tracker status per (CVE, source package, release):
    * `open` → affected_open
    * `resolved` with fixed_version `0` → not_affected
    * `resolved` with a real fixed_version → fixed_in_version
    * `undetermined` is skipped

    Sampling is label-balanced from all userland source packages, excluding `linux*`.
    `nvd_description` is added where NVD was mirrored. D6 has no temporal flag, because NVD dates were
    mirrored only for D1 CVEs.

`docs/DATA_CONTRACT.md` was **not** changed.

## Known weaknesses

* **Scanner baseline is near-perfect on versions.** Natural disagreement is only 1.3% on dev+calib, and all of
  it comes from V5 cases. Any interesting disagreement must come from config, CMDB, or the agent not having
  the scanners.
* **V5 is thin** (7 cases, 1 in test). Config-gating is mainly exercised through `req_config=true` on
  fixed/absent cases, and through V2 cases whose feature is enabled.
* **Fixtures are partial systems.** They contain no dependency closure, a simulated process table, and only
  `etc/`, `var/lib/dpkg/` and `usr/lib/os-release` from the image. The added package docs are only
  `changelog.Debian`. Installed-Size, Maintainer and Description come from the archive-current build even
  when the version is older.
* **V2 versions can be a release's base version.** In-release V2 versions come from snapshot.debian.org with a
  release-marker heuristic. For `+debNNuX` fixes the predecessor can be the release's base version (for
  example 1:9.2p1-2), which the bookworm archive did carry. 14 CVE/release pairs had no qualifying
  predecessor and got no V2.
* **Some decoys are weak.**
  * libcurl3-gnutls (src curl) for gnutls28 CVEs, ruby-rack for ruby, and python3-pip for python.
  * php-common (src php-defaults) is a real dependency-level overlap.
* **Old KEV CVEs have no V2.** 9 of the 22 KEV CVEs land in test, mostly as V1/V3/V6, because their fixes
  predate bookworm.
* **V3/V4 depends on NVD coverage.** 2026 CVEs without NVD CPE data default to V3.
* **The dataset is large.** data/d1 is about 7.4 GB (906 rootfs copies of about 4.5 MB plus about 3.6 GB of
  raw scanner JSON). Committing it to git as-is is not advisable. Consider git-lfs, or a `.gitignore` entry for
  `data/d1/hosts/*/scans/` and `rootfs/` with regeneration via the scripts. All inputs are mirrored, so the
  build is deterministic.
