#!/usr/bin/env Rscript
# GLMM / LMM analysis of E2 (test split) -- V3 plan G8 (plan §8.2 asks for R lme4; v2 used a GEE fallback).
# POST-HOC addition to v2 (logged by the lead in prereg/DEVIATIONS.md); not part of the pre-registered tests.
#
#   .venv/bin/python scripts/stats/export_long.py            # -> results/v3/glmm/e2_test_long.csv
#   .renv/bin/Rscript scripts/stats/glmm.R                    # -> results/v3/glmm_e2.md + results/v3/glmm/*.csv
#
# Models (per arm, reference system S3):
#   M1  glmer(correct ~ system + model + (1|cve) + (1|base_image), binomial)  LLM systems S2-S5 (+DC if not separated)
#   M1b bglmer (blme; weakly-informative N(0, 2.5^2) prior on fixed effects, N(0, 10^2) on the intercept) with DC
#       included in both arms -- the separation-robust sensitivity analysis
#   M1s sensitivity for the random-effect structure: (1|cve) + (1|case_id) + base_image as a fixed effect
#   M2  lmer(loss ~ system + model + (1|cve) + (1|base_image)) with DC (loss is not separated)
#   H6  glmer/bglmer(correct ~ system * log_size_c + (1|model) + (1|cve) + (1|base_image)), LLM systems only
# Wald 95% CIs throughout (confint(method = "Wald")); emmeans per system on the probability / loss scale
# (equal weights over models; asymptotic df).

suppressPackageStartupMessages({
  library(lme4); library(blme); library(emmeans); library(data.table)
})

args <- commandArgs(trailingOnly = FALSE)
script <- sub("^--file=", "", args[grep("^--file=", args)])
root <- normalizePath(file.path(dirname(script), "..", ".."))
inp <- file.path(root, "results", "v3", "glmm", "e2_test_long.csv")
outdir <- file.path(root, "results", "v3", "glmm")
md_path <- file.path(root, "results", "v3", "glmm_e2.md")
dir.create(outdir, showWarnings = FALSE, recursive = TRUE)

d <- fread(inp)
LLM <- c("S3", "S2", "S4", "S5", "DC")
d <- d[system %in% LLM]
d[, system := factor(system, levels = LLM)]
d[, model := factor(model)]
d[, model := relevel(model, ref = "qwen3_14b")]
d[, cve := factor(cve)]
d[, base_image := factor(sub("@.*$", "", base_image))]  # two levels: debian:bookworm-slim / debian:trixie-slim
d[, case_id := factor(case_id)]
d[, log_size_c := log_size - mean(log(unique(d[, .(model, size_b)])$size_b))]
ctrl <- glmerControl(optimizer = "bobyqa", optCtrl = list(maxfun = 2e5))
md <- character()
add <- function(...) md <<- c(md, paste0(...))
fmt <- function(x, k = 3) formatC(x, format = "f", digits = k)
fmtp <- function(p) ifelse(p < 1e-4, "<1e-4", formatC(p, format = "g", digits = 2))

pipe_table <- function(df) {
  df <- as.data.frame(df)
  h <- paste0("| ", paste(names(df), collapse = " | "), " |")
  s <- paste0("|", paste(rep("---", ncol(df)), collapse = "|"), "|")
  rows <- apply(df, 1, function(r) paste0("| ", paste(r, collapse = " | "), " |"))
  c(h, s, rows, "")
}

fixef_table <- function(fit, exp_scale = TRUE) {
  est <- fixef(fit)
  se <- sqrt(diag(as.matrix(vcov(fit))))
  z <- est / se
  lo <- est - qnorm(0.975) * se
  hi <- est + qnorm(0.975) * se
  tr <- if (exp_scale) exp else identity
  data.table(term = names(est), estimate = tr(est), ci_lo = tr(lo), ci_hi = tr(hi), se_link = se,
             z = z, p = 2 * pnorm(-abs(z)))
}

re_table <- function(fit) {
  vc <- as.data.frame(VarCorr(fit))
  data.table(group = vc$grp, sd = vc$sdcor)
}

emm_table <- function(fit, type = "response") {
  e <- emmeans(fit, ~ system, type = type)
  s <- as.data.frame(summary(e, infer = c(TRUE, FALSE)))
  est_col <- intersect(c("prob", "response", "emmean"), names(s))[1]
  lo_col <- intersect(c("asymp.LCL", "lower.CL"), names(s))[1]
  hi_col <- intersect(c("asymp.UCL", "upper.CL"), names(s))[1]
  data.table(system = as.character(s$system), estimate = s[[est_col]], ci_lo = s[[lo_col]], ci_hi = s[[hi_col]])
}

sys_rows <- function(tab) tab[grepl("^system", term)]
show_or <- function(tab) {
  t <- sys_rows(tab)
  data.table(term = sub("^system", "", t$term), OR = fmt(t$estimate), `95% Wald CI` =
               paste0("[", fmt(t$ci_lo), ", ", fmt(t$ci_hi), "]"), p = fmtp(t$p))
}
show_emm <- function(e, k = 3) data.table(system = e$system, estimate = fmt(e$estimate, k),
                                          `95% CI` = paste0("[", fmt(e$ci_lo, k), ", ", fmt(e$ci_hi, k), "]"))
# run a fit + its summaries, collecting every warning/message (reported next to the model, never hidden)
NOISE <- "lmerTest|D.f. calculations|To enable adjustments|or, globally|be warned"
captured <- function(expr) {
  msgs <- character()
  val <- withCallingHandlers(expr,
    warning = function(w) { msgs <<- c(msgs, conditionMessage(w)); invokeRestart("muffleWarning") },
    message = function(m) {
      if (!grepl(NOISE, conditionMessage(m))) msgs <<- c(msgs, trimws(conditionMessage(m)))
      invokeRestart("muffleMessage")
    })
  val$msgs <- unique(gsub("\\s+", " ", msgs))
  val
}
fit_summary <- function(fit_fn, exp_scale = TRUE, type = "response", emm = TRUE) {
  captured({
    f <- fit_fn()
    list(fit = f, tab = fixef_table(f, exp_scale), emm = if (emm) emm_table(f, type) else NULL, re = re_table(f))
  })
}
fit_notes <- function(res) {
  fit <- res$fit
  conv <- fit@optinfo$conv$lme4$messages
  all <- unique(c(conv, res$msgs))
  paste0("isSingular: ", isSingular(fit), if (length(all)) paste0("; warnings/messages during fit and summaries: ",
                                                                  paste(all, collapse = " / ")) else "")
}
wcsv <- function(x, name) fwrite(x, file.path(outdir, name))

# ------------------------------------------------------------------ header + separation check
add("# E2 (test split) GLMM / LMM -- post-hoc addition to v2")
add("")
add("Generated by `scripts/stats/glmm.R` from `results/v3/glmm/e2_test_long.csv` (`scripts/stats/export_long.py`; ",
    "runs/test/E2/*.jsonl joined with the sealed test labels, readable after tag `prereg-v1`). ",
    "**Post-hoc**: the pre-registration (§6) used statsmodels GEE because R/lme4 was unavailable; this ",
    "re-analysis with lme4 ", as.character(packageVersion("lme4")), " / blme ", as.character(packageVersion("blme")),
    " / emmeans ", as.character(packageVersion("emmeans")), " (", R.version.string, ", conda env `.renv`) ",
    "is exploratory and does not replace the pre-registered sign-flip tests.")
add("")
add("Data: LLM systems S2, S3, S4, S5, DC x 6 models x 453 test cases x 2 arms (", nrow(d), " episodes, ",
    nlevels(d$cve), " CVEs, ", nlevels(d$base_image), " base images). LLM-free systems (S0, S1, S1') are excluded: ",
    "they have no model, so `model` would be collinear with them.")
add("Random effects as specified in plan §8.2: `(1|cve) + (1|base_image)`. `base_image` has only two levels ",
    "(bookworm-slim, trixie-slim), so its variance is barely identified (often estimated as 0 -> singular fit); a ",
    "sensitivity model replaces it by a fixed effect and adds a case-level intercept `(1|case_id)` (every case is ",
    "observed under all systems x models).")
add("")
sep <- d[, .(n = .N, correct = sum(correct), acc = mean(correct)), by = .(arm, system)][order(arm, system)]
wcsv(sep, "separation_check.csv")
add("## Separation check (accuracy by arm x system)")
add("")
md <- c(md, pipe_table(sep[, .(arm, system, n, correct, acc = fmt(acc))]))
dc_sep <- sep[system == "DC" & (acc == 1 | acc == 0), arm]
dc_inv <- d[system == "DC", .(sd_acc = sd(.SD[, mean(correct), by = model]$V1)), by = arm]
add("**Perfect separation**: DC is ", paste(sprintf("%s correct in the %s arm", "100%", dc_sep), collapse = ", "),
    " -- its maximum-likelihood log-odds ratio is +infinity and a Wald CI does not exist. Handling: (i) the ",
    "primary GLMM (M1) is fitted on the LLM baselines S2-S5 only in any arm where DC is separated, and DC is reported ",
    "descriptively (exact count above); (ii) M1b refits with DC included using `blme::bglmer` with a weakly ",
    "informative N(0, 2.5^2) prior on the fixed effects (N(0, 10^2) on the intercept), which yields a finite but ",
    "**prior-driven** DC odds ratio whose magnitude must not be interpreted beyond 'very large'. Also note that DC's ",
    "decisions are identical across models (between-model SD of DC accuracy per arm: ",
    paste(sprintf("%s %.3f", dc_inv$arm, dc_inv$sd_acc), collapse = ", "),
    "), so the additive `model` effect does not describe DC.")
add("")

all_or <- list(); all_emm <- list(); all_re <- list(); all_lmm <- list(); all_h6 <- list()
for (a in c("tracker", "withheld")) {
  da <- d[arm == a]
  dc_separated <- a %in% dc_sep
  d1 <- if (dc_separated) droplevels(da[system != "DC"]) else droplevels(da)
  d1[, system := relevel(system, ref = "S3")]
  add("## Arm: ", a)
  add("")
  # ---- M1 glmer
  m1 <- fit_summary(function() glmer(correct ~ system + model + (1 | cve) + (1 | base_image), data = d1,
                                     family = binomial, control = ctrl))
  f1 <- m1; t1 <- m1$tab; e1 <- m1$emm; r1 <- m1$re
  t1[, `:=`(arm = a, fit = "M1_glmer")]; e1[, `:=`(arm = a, fit = "M1_glmer")]; r1[, `:=`(arm = a, fit = "M1_glmer")]
  all_or[[length(all_or) + 1]] <- t1; all_emm[[length(all_emm) + 1]] <- e1; all_re[[length(all_re) + 1]] <- r1
  add("### M1 glmer: correct ~ system + model + (1|cve) + (1|base_image)",
      if (dc_separated) " -- LLM baselines S2-S5 (DC separated, excluded)" else " -- S2-S5 + DC")
  add("")
  add("n = ", nrow(d1), "; ", fit_notes(f1), "; random-effect SDs (logit): ",
      paste(sprintf("%s %.3f", r1$group, r1$sd), collapse = ", "), ".")
  add("")
  add("Odds ratios vs S3 (adjusted for model):")
  add("")
  md <- c(md, pipe_table(show_or(t1)))
  add("Estimated marginal probability of a correct decision (emmeans, averaged over models):")
  add("")
  md <- c(md, pipe_table(show_emm(e1)))
  # ---- M1b bglmer with DC
  d2 <- droplevels(da); d2[, system := relevel(system, ref = "S3")]
  m2 <- fit_summary(function() bglmer(correct ~ system + model + (1 | cve) + (1 | base_image), data = d2,
                                      family = binomial, control = ctrl, fixef.prior = normal(sd = c(10, 2.5))))
  f2 <- m2; t2 <- m2$tab; e2 <- m2$emm; r2 <- m2$re
  t2[, `:=`(arm = a, fit = "M1b_bglmer")]; e2[, `:=`(arm = a, fit = "M1b_bglmer")]; r2[, `:=`(arm = a, fit = "M1b_bglmer")]
  all_or[[length(all_or) + 1]] <- t2; all_emm[[length(all_emm) + 1]] <- e2; all_re[[length(all_re) + 1]] <- r2
  add("### M1b bglmer (weakly informative prior), S2-S5 + DC")
  add("")
  add("n = ", nrow(d2), "; ", fit_notes(f2), ".", if (dc_separated) " DC row is prior-driven (separation)." else "")
  add("")
  md <- c(md, pipe_table(show_or(t2)))
  md <- c(md, pipe_table(show_emm(e2)))
  # ---- M1s random-effect sensitivity
  m3 <- fit_summary(function() glmer(correct ~ system + model + base_image + (1 | cve) + (1 | case_id), data = d1,
                                     family = binomial, control = ctrl), emm = FALSE)
  f3 <- m3; t3 <- m3$tab; r3 <- m3$re
  t3[, `:=`(arm = a, fit = "M1s_glmer_case")]; r3[, `:=`(arm = a, fit = "M1s_glmer_case")]
  all_or[[length(all_or) + 1]] <- t3; all_re[[length(all_re) + 1]] <- r3
  add("### M1s sensitivity: correct ~ system + model + base_image + (1|cve) + (1|case_id) (same systems as M1)")
  add("")
  add(fit_notes(f3), "; random-effect SDs: ", paste(sprintf("%s %.3f", r3$group, r3$sd), collapse = ", "), ".")
  add("")
  md <- c(md, pipe_table(show_or(t3)))
  # ---- M2 lmer on loss (all LLM systems incl. DC)
  m4 <- fit_summary(function() lmer(loss ~ system + model + (1 | cve) + (1 | base_image), data = d2, REML = TRUE),
                    exp_scale = FALSE, type = "link")
  f4 <- m4; t4 <- m4$tab; e4 <- m4$emm; r4 <- m4$re
  t4[, `:=`(arm = a, fit = "M2_lmer_loss")]; e4[, `:=`(arm = a, fit = "M2_lmer_loss")]; r4[, `:=`(arm = a, fit = "M2_lmer_loss")]
  all_lmm[[length(all_lmm) + 1]] <- t4; all_emm[[length(all_emm) + 1]] <- e4; all_re[[length(all_re) + 1]] <- r4
  add("### M2 lmer: loss ~ system + model + (1|cve) + (1|base_image), S2-S5 + DC")
  add("")
  add("n = ", nrow(d2), "; ", fit_notes(f4), "; residual and random-effect SDs: ",
      paste(sprintf("%s %.3f", r4$group, r4$sd), collapse = ", "),
      ". Loss is a bounded, highly skewed outcome (0 / 0.2 / 0.5 / 1 / 10); Wald CIs from a Gaussian LMM are a ",
      "descriptive approximation (normal reference distribution, large n).")
  add("")
  tl <- sys_rows(t4)
  md <- c(md, pipe_table(data.table(term = sub("^system", "", tl$term), `diff vs S3` = fmt(tl$estimate),
                                    `95% Wald CI` = paste0("[", fmt(tl$ci_lo), ", ", fmt(tl$ci_hi), "]"),
                                    p = fmtp(tl$p))))
  add("Estimated marginal mean loss (emmeans):")
  add("")
  md <- c(md, pipe_table(show_emm(e4)))
}

# ------------------------------------------------------------------ H6: system x log(size), LLM systems
add("## H6 (exploratory): system x log(model size), LLM systems")
add("")
add("`correct ~ system * log_size_c + (1|model) + (1|cve) + (1|base_image)` per arm, reference S3; `log_size_c` = ",
    "log(size in B parameters) centred on the panel mean; `(1|model)` added because size is a model-level covariate ",
    "with only 6 models (without it, model-to-model differences unrelated to size would be attributed to size with ",
    "overconfident SEs). Coefficients are on the log-odds scale; `systemX:log_size_c` is the difference between ",
    "system X's and S3's size slope. DC is included via bglmer where it is separated (tracker arm), via glmer ",
    "otherwise. The pre-registered H6 contrast (DC - S3 gain vs size) is the negative of the S3 slope whenever DC ",
    "is model-invariant, which it is (see above).")
add("")
for (a in c("tracker", "withheld")) {
  da <- droplevels(d[arm == a]); da[, system := relevel(system, ref = "S3")]
  dc_separated <- a %in% dc_sep
  # (a) LLM baselines only, glmer
  db <- droplevels(da[system != "DC"]); db[, system := relevel(system, ref = "S3")]
  h1 <- fit_summary(function() glmer(correct ~ system * log_size_c + (1 | model) + (1 | cve) + (1 | base_image),
                                     data = db, family = binomial, control = ctrl), exp_scale = FALSE, emm = FALSE)
  th1 <- h1$tab; th1[, `:=`(arm = a, fit = "H6_glmer_baselines")]
  # (b) with DC
  h2 <- fit_summary(function() if (dc_separated) {
    bglmer(correct ~ system * log_size_c + (1 | model) + (1 | cve) + (1 | base_image), data = da, family = binomial,
           control = ctrl, fixef.prior = normal(sd = c(10, 2.5)))
  } else {
    glmer(correct ~ system * log_size_c + (1 | model) + (1 | cve) + (1 | base_image), data = da, family = binomial,
          control = ctrl)
  }, exp_scale = FALSE, emm = FALSE)
  th2 <- h2$tab
  th2[, `:=`(arm = a, fit = if (dc_separated) "H6_bglmer_withDC" else "H6_glmer_withDC")]
  all_h6[[length(all_h6) + 1]] <- th1; all_h6[[length(all_h6) + 1]] <- th2
  for (pair in list(list(h1, th1, "S2-S5 (glmer)"),
                    list(h2, th2, paste0("S2-S5 + DC (", if (dc_separated) "bglmer; DC separated" else "glmer", ")")))) {
    add("### ", a, " arm, ", pair[[3]])
    add("")
    add(fit_notes(pair[[1]]))
    add("")
    t <- pair[[2]][grepl("log_size_c", term)]
    md <- c(md, pipe_table(data.table(term = t$term, `coef (logit)` = fmt(t$estimate),
                                      `95% Wald CI` = paste0("[", fmt(t$ci_lo), ", ", fmt(t$ci_hi), "]"),
                                      p = fmtp(t$p))))
  }
}

wcsv(rbindlist(all_or), "glmm_correct_fixef.csv")
wcsv(rbindlist(all_emm), "emmeans_by_system.csv")
wcsv(rbindlist(all_re), "random_effects.csv")
wcsv(rbindlist(all_lmm), "lmm_loss_fixef.csv")
wcsv(rbindlist(all_h6), "h6_size_interaction.csv")
add("## Notes on interpretation")
add("")
add("* Odds ratios are conditional on the random effects, so they are not comparable across random-effect ",
    "structures: adding `(1|case_id)` (M1s) absorbs most between-case heterogeneity (case SD ~2-3 on the logit ",
    "scale, CVE SD -> 0, singular) and inflates conditional ORs away from 1 (non-collapsibility); the direction ",
    "and significance pattern is what to compare between M1 and M1s.")
add("* Where DC is separated (tracker arm) only the bglmer rows give a DC odds ratio, and that number is set by ",
    "the prior; the substantive statement is the exact count (DC correct in every tracker episode).")
add("* M2 treats a 0/0.2/0.5/1/10 loss as Gaussian; marginal means can fall slightly below 0 (DC). The ",
    "loss differences reproduce the per-episode mean differences of the pre-registered H1 analysis.")
add("* H6: DC's decisions do not depend on the model, so `systemDC:log_size_c` is (minus) the S3 size slope ",
    "estimated within the panel; a negative value means 'the DC - S3 gain shrinks with size' only because S3 ",
    "improves with size. In the tracker arm the DC interaction is prior-driven (separation) and uninformative.")
add("")
add("## Files")
add("")
add("* `results/v3/glmm/e2_test_long.csv` -- long data (one row per episode)")
add("* `results/v3/glmm/glmm_correct_fixef.csv` -- all fixed effects of M1 / M1b / M1s (OR scale, Wald CIs)")
add("* `results/v3/glmm/lmm_loss_fixef.csv` -- M2 fixed effects (loss scale)")
add("* `results/v3/glmm/emmeans_by_system.csv` -- marginal means per system (M1, M1b: probability; M2: loss)")
add("* `results/v3/glmm/random_effects.csv`, `separation_check.csv`, `h6_size_interaction.csv` (logit scale)")
writeLines(md, md_path)
cat("wrote", md_path, "\n")
