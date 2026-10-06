# prereg-v4 analysis (scripts/paper/analyze_v4.py)

## H16 — DCv21b note faithfulness non-inferior to DC (fresh sample, margin −0.02)

- DCv21b 0.744 vs DC 0.700; difference +0.044 [+0.014, +0.073] (504 pairs, 2026/1914 claims, 70 CVEs); **supported**

## H17 — DCt (scanner trust estimated on dev+calib) vs DC, D7 test withheld arm

- loss DCt 0.207 vs DC 0.344: -0.137 [-0.167, -0.107], sign-flip p = 9.999e-05 (n = 3312, 70 CVEs)
- DER DCt 0.000 vs DC 0.000: +0.000 [+0.000, +0.000] (margin 0.01)
- coverage DCt 0.734 vs DC 0.312
- **supported**

|                                |   n |   loss |   coverage |
|:-------------------------------|----:|-------:|-----------:|
| ('DC', 'gemma4_31b')           | 414 | 0.3442 |     0.3116 |
| ('DC', 'granite41_30b')        | 414 | 0.3442 |     0.3116 |
| ('DC', 'granite41_8b')         | 414 | 0.3442 |     0.3116 |
| ('DC', 'llama31_8b')           | 414 | 0.3442 |     0.3116 |
| ('DC', 'mistral_medium_128b')  | 414 | 0.3442 |     0.3116 |
| ('DC', 'mistral_small_24b')    | 414 | 0.3442 |     0.3116 |
| ('DC', 'qwen3_14b')            | 414 | 0.3442 |     0.3116 |
| ('DC', 'qwen3_4b')             | 414 | 0.3442 |     0.3116 |
| ('DCt', 'gemma4_31b')          | 414 | 0.2072 |     0.7343 |
| ('DCt', 'granite41_30b')       | 414 | 0.2072 |     0.7343 |
| ('DCt', 'granite41_8b')        | 414 | 0.2072 |     0.7343 |
| ('DCt', 'llama31_8b')          | 414 | 0.2072 |     0.7343 |
| ('DCt', 'mistral_medium_128b') | 414 | 0.2072 |     0.7343 |
| ('DCt', 'mistral_small_24b')   | 414 | 0.2072 |     0.7343 |
| ('DCt', 'qwen3_14b')           | 414 | 0.2072 |     0.7343 |
| ('DCt', 'qwen3_4b')            | 414 | 0.2072 |     0.7343 |

## H18 — decoy version mentions in read documents (tracker arm): DC loss non-inferior to clean

| system      |   n |   cves |   loss_decoy |   loss_clean |    diff |      lo |      hi |   p_signflip |   seen |   accepted |
|:------------|----:|-------:|-------------:|-------------:|--------:|--------:|--------:|-------------:|-------:|-----------:|
| DC          | 832 |     38 |       0.0409 |       0.0673 | -0.0264 | -0.0502 | -0.0057 |       0.0293 | 0.1346 |          0 |
| DC_noverify | 832 |     38 |       0.0204 |       0.0204 |  0      |  0      |  0      |       1      | 0.1346 |          0 |
| S3          | 832 |     38 |       1.7976 |       1.9011 | -0.1035 | -0.2379 |  0.0304 |       0.5477 | 0.1058 |          0 |

- DC decoy − clean -0.026 [-0.050, -0.006], margin 0.05: **supported**

