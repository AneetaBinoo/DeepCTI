# E0 mixed model (scripts/inquiry/e0_glmm.R)

n = 19096 episodes (LLM agents, gold = affected), 149 CVEs, 10 models; R 4.5.3, lme4 2.0.6.

glmer(dangerous ~ omission + wasted_share + model + dataset + (1 | cve), binomial); Wald 95% CI.

| term | estimate | SE | odds ratio [95% CI] | p |
|---|---:|---:|---|---:|
| omission | 0.938 | 0.044 | 2.55 [2.35, 2.78] | 1.2e-102 |
| wasted_share | -0.096 | 0.068 | 0.91 [0.80, 1.04] | 0.157 |

Singular fit: FALSE; convergence messages: 
