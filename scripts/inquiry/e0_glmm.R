#!/usr/bin/env Rscript
# E0 mixed model (Paper 2): does a critical omission predict a dangerous error beyond wasted questions?
#   .venv/bin/python scripts/inquiry/analyze_e0.py      # -> results/inquiry/e0/e0_long.csv
#   .renv/bin/Rscript scripts/inquiry/e0_glmm.R          # -> results/inquiry/e0/glmm.md
# Model (LLM agents S3/S4/S5/S3I, gold = affected, test split):
#   glmer(dangerous ~ omission + wasted_share + model + dataset + (1 | cve), binomial)
# Wald 95% CIs; odds ratios reported.
suppressPackageStartupMessages({ library(lme4); library(data.table) })
args <- commandArgs(trailingOnly = FALSE)
script <- sub("^--file=", "", args[grep("^--file=", args)])
root <- normalizePath(file.path(dirname(script), "..", ".."))
d <- fread(file.path(root, "results", "inquiry", "e0", "e0_long.csv"))
d[, dangerous := as.integer(as.logical(dangerous))]
d[, omission := as.integer(as.logical(omission))]
d[, model := relevel(factor(model), ref = "qwen3_14b")]
d[, dataset := factor(dataset)]
d[, cve := factor(cve)]
ctrl <- glmerControl(optimizer = "bobyqa", optCtrl = list(maxfun = 2e5))
m <- glmer(dangerous ~ omission + wasted_share + model + dataset + (1 | cve), data = d, family = binomial,
           control = ctrl)
co <- summary(m)$coefficients
ci <- confint(m, method = "Wald", parm = "beta_")
keep <- c("omission", "wasted_share")
out <- data.table(term = keep, estimate = co[keep, "Estimate"], se = co[keep, "Std. Error"],
                  OR = exp(co[keep, "Estimate"]), OR_lo = exp(ci[keep, 1]), OR_hi = exp(ci[keep, 2]),
                  p = co[keep, "Pr(>|z|)"])
md <- c("# E0 mixed model (scripts/inquiry/e0_glmm.R)", "",
        sprintf("n = %d episodes (LLM agents, gold = affected), %d CVEs, %d models; R %s, lme4 %s.",
                nrow(d), nlevels(d$cve), nlevels(d$model), getRversion(), packageVersion("lme4")), "",
        "glmer(dangerous ~ omission + wasted_share + model + dataset + (1 | cve), binomial); Wald 95% CI.", "",
        "| term | estimate | SE | odds ratio [95% CI] | p |", "|---|---:|---:|---|---:|",
        sprintf("| %s | %.3f | %.3f | %.2f [%.2f, %.2f] | %.3g |", out$term, out$estimate, out$se, out$OR,
                out$OR_lo, out$OR_hi, out$p),
        "", sprintf("Singular fit: %s; convergence messages: %s", isSingular(m),
                    paste(m@optinfo$conv$lme4$messages, collapse = "; ")))
writeLines(md, file.path(root, "results", "inquiry", "e0", "glmm.md"))
cat(md, sep = "\n")
