These findings cover 62 tasks, 2 models and 3 seeds, with all numbers taken from the tables above.

1. **No headline improvement.** On VEX-Bench's own metrics, the evidence-state wrapper (B) did not improve on the open harness (A). Every paired task-level bootstrap 95% CI for B − A contains 0.
   * Status F1: Gemma 0.648 → 0.613; Qwen 0.217 → 0.130.
   * Justification macro-F1: Gemma 0.395 → 0.351; Qwen 0.156 → 0.205.
   * The point estimates are negative for status F1 on both models. For macro-F1 they are mixed: −0.045 on Gemma and +0.048 on Qwen.
   * Read this as a null-to-negative transfer result.
2. **High abstention is the main mechanism.** B abstained (emitted `uncertain`) on 54% (Gemma) and 73% (Qwen) of runs.
   * Most abstentions come from R7, where the dependency was verified but reachability was never resolved: 98 of 186 Gemma runs and 92 of 186 Qwen runs. Qwen also hit R3, an unverified dependency, 43 times, largely because it stopped calling tools.
   * The verifier rejected about half of the Gemma proposals (551 rejected vs 522 accepted) and 69% of Qwen's (812 vs 364).
   * The most common rejections are reachability chains whose last span lacks an advisory symbol, and "package never referenced" claims contradicted by the verifier's own search.
   * The models often cannot produce a checkable entry-to-call-site chain within 30 tool calls. VEX-Bench scores `uncertain` as wrong for every ground-truth category.
3. **B is more often right on category when it commits, but worse on status.** On exactly the (task, seed) pairs where B committed:
   * Category accuracy: B is higher, 0.718 vs 0.682 for A (Gemma) and 0.529 vs 0.294 (Qwen).
   * Status accuracy: B is lower, 0.824 vs 0.918 (Gemma) and 0.725 vs 0.804 (Qwen).
   * Overall, B raises Gemma's status precision (0.655 vs 0.556) and lowers its recall (0.578 vs 0.778).
   * So the discipline buys calibrated, evidence-backed categories on a minority of cases. It does not buy a better exploitability call.
4. **B costs much more.** B used 2.6× (Qwen) to 3.9× (Gemma) the tokens per case, and Gemma's mean tool calls rose from 9.1 to 16.4. A, by contrast, usually answers well before the 30-call budget.
5. **Model capability dominates the system choice.** Qwen3-14B performs poorly under both systems: its A status F1 of 0.217 is below the always-`vulnerable` baseline of 0.390. Qwen-A over-uses `code_not_present` (96 of 186 runs), even though only 4 of the 62 subset tasks carry that label.

**Caveats:**
* The subset and the offline advisory digest (see Deviations) make absolute numbers non-comparable with the VEX-Bench paper.
* B's rule cannot output requires_environment or the protection categories.
* The design choices (strict verbatim spans, the 4-call mitigation window, reachability needing a symbol-bearing last span) were fixed after a 5-task pilot and were not tuned on these results. A looser reachability check would change the abstention rate and is untested here.
