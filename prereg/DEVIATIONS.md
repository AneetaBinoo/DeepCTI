# Deviations after tag prereg-v1

Every change to code, data, analysis or execution after `prereg-v1` is listed here with its reason and its
effect on reported numbers. (Deviations from the original plan made BEFORE the tag are documented in
prereg/PREREGISTRATION.md §7 and docs/PHASE_REPORTS.md.)

| # | time (UTC) | change | reason | affects |
|---|---|---|---|---|
| — | 05:39 | none: D2/D3 test episodes built after the tag with the frozen generator, as pre-registered | — | — |
| D1 | 05:50 | E6: candidate threshold grid built from the calibration fold only; E6 refuses to run if calib or test DC records are missing | code audit R2 F7: grid previously included evaluation folds (mild leakage) and could silently fall back to one split | E6/H5 only |
| D2 | 05:50 | new "Sensitivity analyses" section in scripts/paper/analyze.py; the pre-registered primary analysis is unchanged | code audit R2 (docs/audit/CODE_AUDIT_R2.md) | adds exploratory numbers only |
| D3 | 05:50 | H2 also reported on D2 episodes whose status changed (F1) | 20% of D2 episodes (upgrade without restart keeps `affected`; config_enable lacks config evidence in history) cannot produce a staleness error and dilute H2 | sensitivity |
| D4 | 05:50 | H3 also reported on cost-to-decision (F6) | primary uses total tool cost incl. remediation calls after the decision | sensitivity |
| D5 | 05:50 | m-attacker ASR/UDAR split by whether the forgery changes any evidence (F2) | D3 generator sometimes forges the true version | sensitivity |
| D6 | 05:50 | compromised-change UDAR split by true rollback availability (F3) | forged tickets cannot set rollback; apply_patch also gates on rollback | sensitivity |
| D7 | 05:50 | untrusted-attacker ASR minus the goal condition's benign rate (F9) | ASR includes ordinary errors | sensitivity |
