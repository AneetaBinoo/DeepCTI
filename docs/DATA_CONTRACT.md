# DeepCTI v2 — data contract (D1 DeepCTI‑Live, D6, mirrors)

This file fixes the interface between the data pipeline (`scripts/data/`) and the
experiment code (`src/deepcti/`). Change it only together with both sides.

## Environment deviation (recorded in docs/VERIFICATION_LOG.md)

The experiment host has no Docker/Podman/Apptainer and no root. Hosts are therefore
**rootfs fixtures**: a directory with a real `etc/os-release`, a real
`var/lib/dpkg/status` (taken from the official `debian:<release>-slim` image layers,
fetched through the Docker Registry v2 HTTP API, then extended with target‑package
stanzas whose versions are real Debian versions from snapshot.debian.org), real
configuration files where a CVE is configuration‑gated, a simulated process table, and a
CMDB record. Scanners (Trivy, Grype, OSV‑Scanner) run for real against the fixture
directory. The agent never executes anything inside the fixture: tools read the fixture
into an in‑memory host model (`deepcti.env.host`). No exploit code exists anywhere.

## Directory layout

```
data/mirrors/<source>/<YYYY-MM-DD>/MANIFEST.json   url, retrieved_at, sha256, bytes, license
data/mirrors/<source>/<YYYY-MM-DD>/...             raw files (large raw/ subdirs are git‑ignored)
data/d1/hosts/<host_id>/rootfs/...                 fixture filesystem
data/d1/hosts/<host_id>/host.json                  services, cmdb, metadata (see below)
data/d1/hosts/<host_id>/scans/{trivy,grype,osv}.json   raw scanner output (whole host)
data/d1/cases/{dev,calib}.jsonl                    cases with labels
data/d1/cases/test.jsonl                           test cases WITHOUT label fields
data/sealed/test_labels.jsonl                      test labels (hash recorded in prereg)
data/d1/cve_meta.jsonl                             one row per CVE (see below)
data/d1/BUILD_REPORT.md                            counts per split/variant/family, natural
                                                   scanner disagreement rate, failures
data/d6/{dev,calib,test}.jsonl                     advisory‑to‑status tuples
```

## `cve_meta.jsonl` row

```json
{"cve": "CVE-2024-6387", "src_package": "openssh", "family": "ssh",
 "published": "2024-07-01", "kev": true, "epss": 0.97,
 "description": "...", "debian": {"bookworm": {"status": "resolved", "fixed_version": "1:9.2p1-2+deb12u3", "urgency": "..."}, ...},
 "nvd_ranges": [{"cpe": "...", "versionStartIncluding": "...", "versionEndExcluding": "..."}],
 "osv_ids": ["DSA-..."], "config_precondition": null | {"file": "etc/ssh/sshd_config", "key": "...", "vulnerable_when": "...", "safe_value": "...", "source": "<advisory url>"},
 "split": "dev|calib|test", "temporal_holdout": false}
```

## Case row (`cases/*.jsonl`)

```json
{"case_id": "D1-CVE-2024-6387-bookworm-V2", "cve": "CVE-2024-6387", "src_package": "openssh",
 "binary_packages": ["openssh-server", "openssh-client"], "distro": "debian", "release": "bookworm",
 "variant": "V1|V2|V3|V4|V5|V6", "host_id": "h_...", "family": "ssh", "split": "dev",
 "temporal_holdout": false, "kev": true, "base_image": "debian:bookworm-slim@sha256:...",
 "installed_version": "1:9.2p1-2+deb12u2" | null,
 "label": {"status": "affected|not_affected|fixed", "justification": null | "component_not_present" | "vulnerable_code_not_present" | "requires_configuration"},
 "atoms": {"present": true, "in_affected_range": true, "fix_applied": false,
           "vuln_config_enabled": true, "req_config": false},
 "label_provenance": "debian-tracker@<date> + dpkg --compare-versions"}
```

For test cases the fields `label` and `atoms` are removed from `cases/test.jsonl` and
written with `case_id` to `data/sealed/test_labels.jsonl`.

## Atom semantics (ground truth)

* `present` — some binary package built from `src_package` is installed (`Status: install ok installed`).
* `in_affected_range` — present and (tracker status `open`/`undetermined` with no fixed version, or
  installed version `<` tracker `fixed_version` for that release, compared with `dpkg --compare-versions`
  semantics via `python-debian`). `fixed_version == "0"` (not affected in that release) → false.
* `fix_applied` — present, tracker `fixed_version` exists and is not `"0"`, and installed version `>=` it.
* `req_config` — the CVE has a curated configuration precondition (`config/config_preconditions.yaml`).
* `vuln_config_enabled` — the fixture configuration enables the vulnerable feature (only meaningful if `req_config`).

Label = §3.4 decision table applied to the true atoms:
not present → not_affected/component_not_present; fix_applied → fixed;
not in range → not_affected/vulnerable_code_not_present; req_config ∧ ¬config → not_affected/requires_configuration;
otherwise affected.

## Variants

| Variant | Construction |
|---|---|
| V1 absent | base image without any binary of `src_package` |
| V2 vulnerable | real Debian version for the release that is `<` fixed_version (or any version if open) |
| V3 fixed | real version `>=` fixed_version whose upstream part is also outside the NVD range (if one exists) |
| V4 backport | real version `>=` fixed_version whose upstream part is inside the NVD range (naive upstream compare says vulnerable) |
| V5 config‑gated | V2 + config disabling the vulnerable feature (only CVEs with a curated precondition) |
| V6 decoy | a different source package whose name/vendor overlaps the advisory (e.g. `python3-openssl` for an OpenSSL CVE) |

## `host.json`

```json
{"host_id": "h_...", "hostname": "srv-...", "release": "bookworm",
 "services": {"ssh": {"unit": "ssh.service", "active": true, "package": "openssh-server"}},
 "cmdb": {"asset": "srv-...", "os": "Debian 12", "software": [{"name": "openssh-server", "version": "..."}],
          "last_sync": "2026-...", "notes": "free text"},
 "cmdb_stale": false,
 "change": {"ticket": null | {"id": "CHG-...", "approved": true, "window_open": true}},
 "rollback_available": true}
```

`cmdb_stale` hosts carry a CMDB record built from an earlier state of the host (documented
perturbation, seeded). Scanner outputs are whole‑host; tools filter them to the case CVE.
