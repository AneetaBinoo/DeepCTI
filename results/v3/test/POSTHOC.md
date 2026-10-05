# Post-hoc / exploratory v3 analyses (scripts/paper/analyze_v3_posthoc.py)

Nothing here belongs to a pre-registered hypothesis family; see prereg/DEVIATIONS.md.

## X2V — vendor cases with the fixed verifier (D21) vs the pre-registered run

|                                               |   n |    acc |   coverage |   loss |   cost |   DER |
|:----------------------------------------------|----:|-------:|-----------:|-------:|-------:|------:|
| ('blind', 'DC', 'fixed (D21)')                | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('blind', 'DC', 'pre-registered')             | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('blind', 'DC_noverify', 'fixed (D21)')       | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('blind', 'DC_noverify', 'pre-registered')    | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('blind', 'DCv21', 'fixed (D21)')             | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('blind', 'DCv21', 'pre-registered')          | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('blind', 'S1p', 'fixed (D21)')               |  84 | 0.2976 |     0.2976 | 0.3512 | 2.7024 |     0 |
| ('blind', 'S1p', 'pre-registered')            |  84 | 0.2976 |     0.2976 | 0.3512 | 2.7024 |     0 |
| ('tracker', 'DC', 'fixed (D21)')              | 588 | 0.7704 |     0.7704 | 0.1148 | 4.7126 |     0 |
| ('tracker', 'DC', 'pre-registered')           | 588 | 0.7058 |     0.716  | 0.1522 | 4.6412 |     0 |
| ('tracker', 'DC_noverify', 'fixed (D21)')     | 588 | 0.8282 |     0.8537 | 0.0864 | 4.6633 |     0 |
| ('tracker', 'DC_noverify', 'pre-registered')  | 588 | 0.8282 |     0.8537 | 0.0864 | 4.6684 |     0 |
| ('tracker', 'DCv21', 'fixed (D21)')           | 588 | 0.7075 |     0.7075 | 0.1463 | 5.1259 |     0 |
| ('tracker', 'DCv21', 'pre-registered')        | 588 | 0.6854 |     0.7007 | 0.165  | 5.0901 |     0 |
| ('tracker', 'S1p', 'fixed (D21)')             |  84 | 0.2976 |     0.2976 | 0.3512 | 2.869  |     0 |
| ('tracker', 'S1p', 'pre-registered')          |  84 | 0.2976 |     0.2976 | 0.3512 | 2.869  |     0 |
| ('withheld', 'DC', 'fixed (D21)')             | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('withheld', 'DC', 'pre-registered')          | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('withheld', 'DC_noverify', 'fixed (D21)')    | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('withheld', 'DC_noverify', 'pre-registered') | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('withheld', 'DCv21', 'fixed (D21)')          | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('withheld', 'DCv21', 'pre-registered')       | 588 | 0.2976 |     0.2976 | 0.3512 | 6.6548 |     0 |
| ('withheld', 'S1p', 'fixed (D21)')            |  84 | 0.2976 |     0.2976 | 0.3512 | 2.7024 |     0 |
| ('withheld', 'S1p', 'pre-registered')         |  84 | 0.2976 |     0.2976 | 0.3512 | 2.7024 |     0 |

## S3I (Inspect AI react) vs S3 on D7

|                                          |   n |    acc |   coverage |   loss |   cost |    DER |
|:-----------------------------------------|----:|-------:|-----------:|-------:|-------:|-------:|
| ('tracker', 'mistral_small_24b', 'S3')   | 414 | 0.7005 |     0.9928 | 0.8394 | 4.7126 | 0.1959 |
| ('tracker', 'mistral_small_24b', 'S3I')  | 414 | 0.6763 |     0.9903 | 0.9237 | 5.0435 | 0.2162 |
| ('tracker', 'qwen3_14b', 'S3')           | 414 | 0.7222 |     1      | 1.1329 | 4.9952 | 0.2838 |
| ('tracker', 'qwen3_14b', 'S3I')          | 414 | 0.7053 |     0.9928 | 1.1403 | 5.3164 | 0.2838 |
| ('withheld', 'mistral_small_24b', 'S3')  | 414 | 0.5338 |     0.9589 | 1.6302 | 6.4952 | 0.4054 |
| ('withheld', 'mistral_small_24b', 'S3I') | 414 | 0.5676 |     0.9807 | 1.4986 | 6.2077 | 0.3716 |
| ('withheld', 'qwen3_14b', 'S3')          | 414 | 0.5193 |     0.9928 | 2.1423 | 6.2971 | 0.5608 |
| ('withheld', 'qwen3_14b', 'S3I')         | 414 | 0.57   |     0.9879 | 1.5138 | 6.2947 | 0.3784 |

Decision agreement S3I = S3: 0.806 (n = 1635)

## Scaling — D1 E2: S3 (ReAct) and DC loss by model (incl. addendum models)

| arm      | system   | model               |   n |   loss |    acc |   size_b |
|:---------|:---------|:--------------------|----:|-------:|-------:|---------:|
| tracker  | DC       | qwen3_4b            | 453 | 0      | 1      |        4 |
| tracker  | DC       | granite41_8b        | 453 | 0      | 1      |        8 |
| tracker  | DC       | llama31_8b          | 453 | 0      | 1      |        8 |
| tracker  | DC       | qwen3_14b           | 453 | 0      | 1      |       14 |
| tracker  | DC       | mistral_small_24b   | 453 | 0      | 1      |       24 |
| tracker  | DC       | granite41_30b       | 453 | 0      | 1      |       30 |
| tracker  | DC       | gemma4_31b          | 453 | 0      | 1      |       31 |
| tracker  | DC       | nemotron_super_49b  | 453 | 0      | 1      |       49 |
| tracker  | DC       | mistral_medium_128b | 453 | 0      | 1      |      128 |
| tracker  | S3       | qwen3_4b            | 453 | 2.6364 | 0.6733 |        4 |
| tracker  | S3       | granite41_8b        | 453 | 0.9563 | 0.8322 |        8 |
| tracker  | S3       | llama31_8b          | 453 | 1.7711 | 0.4702 |        8 |
| tracker  | S3       | qwen3_14b           | 453 | 0.3464 | 0.9272 |       14 |
| tracker  | S3       | mistral_small_24b   | 453 | 0.6393 | 0.8675 |       24 |
| tracker  | S3       | granite41_30b       | 453 | 0.4397 | 0.8918 |       30 |
| tracker  | S3       | gemma4_31b          | 453 | 0.177  | 0.9801 |       31 |
| tracker  | S3       | nemotron_super_49b  | 453 | 1.7139 | 0.2406 |       49 |
| tracker  | S3       | mistral_medium_128b | 453 | 0.4093 | 0.9227 |      128 |
| withheld | DC       | qwen3_4b            | 453 | 0.0671 | 0.6733 |        4 |
| withheld | DC       | granite41_8b        | 453 | 0.0671 | 0.6733 |        8 |
| withheld | DC       | llama31_8b          | 453 | 0.0671 | 0.6733 |        8 |
| withheld | DC       | qwen3_14b           | 453 | 0.0671 | 0.6733 |       14 |
| withheld | DC       | mistral_small_24b   | 453 | 0.0671 | 0.6733 |       24 |
| withheld | DC       | granite41_30b       | 453 | 0.0671 | 0.6733 |       30 |
| withheld | DC       | gemma4_31b          | 453 | 0.0671 | 0.6733 |       31 |
| withheld | DC       | nemotron_super_49b  | 453 | 0.0671 | 0.6733 |       49 |
| withheld | DC       | mistral_medium_128b | 453 | 0.0671 | 0.6733 |      128 |
| withheld | S3       | qwen3_4b            | 453 | 1.5523 | 0.5453 |        4 |
| withheld | S3       | granite41_8b        | 453 | 1.5993 | 0.6049 |        8 |
| withheld | S3       | llama31_8b          | 453 | 2.4424 | 0.3753 |        8 |
| withheld | S3       | qwen3_14b           | 453 | 2.5124 | 0.426  |       14 |
| withheld | S3       | mistral_small_24b   | 453 | 1.0971 | 0.6004 |       24 |
| withheld | S3       | granite41_30b       | 453 | 0.645  | 0.4283 |       30 |
| withheld | S3       | gemma4_31b          | 453 | 0.7088 | 0.7241 |       31 |
| withheld | S3       | nemotron_super_49b  | 453 | 1.6974 | 0.234  |       49 |
| withheld | S3       | mistral_medium_128b | 453 | 0.8552 | 0.6998 |      128 |

- D1 tracker: S3[mistral_medium_128b] − DC loss on 453 matched cases: 0.409 [0.227, 0.627], sign-flip p = 9.999e-05
- D1 withheld: S3[mistral_medium_128b] − DC loss on 453 matched cases: 0.788 [0.538, 1.090], sign-flip p = 9.999e-05
- D1 tracker: S3[nemotron_super_49b] − DC loss on 453 matched cases: 1.714 [1.443, 1.998], sign-flip p = 9.999e-05
- D1 withheld: S3[nemotron_super_49b] − DC loss on 453 matched cases: 1.630 [1.371, 1.875], sign-flip p = 9.999e-05
- D1 tracker: S3[granite41_30b] − DC loss on 453 matched cases: 0.440 [0.287, 0.617], sign-flip p = 9.999e-05
- D1 withheld: S3[granite41_30b] − DC loss on 453 matched cases: 0.578 [0.406, 0.759], sign-flip p = 9.999e-05

## Scaling — D7 X2: S3 (ReAct) and DC loss by model (incl. addendum models)

| arm      | system   | model             |   n |   loss |    acc |   size_b |
|:---------|:---------|:------------------|----:|-------:|-------:|---------:|
| blind    | DC       | qwen3_4b          | 414 | 0.3442 | 0.3116 |        4 |
| blind    | DC       | granite41_8b      | 414 | 0.3442 | 0.3116 |        8 |
| blind    | DC       | llama31_8b        | 414 | 0.3442 | 0.3116 |        8 |
| blind    | DC       | qwen3_14b         | 414 | 0.3442 | 0.3116 |       14 |
| blind    | DC       | mistral_small_24b | 414 | 0.3442 | 0.3116 |       24 |
| blind    | DC       | granite41_30b     | 414 | 0.3442 | 0.3116 |       30 |
| blind    | DC       | gemma4_31b        | 414 | 0.3442 | 0.3116 |       31 |
| blind    | S3       | qwen3_4b          | 414 | 1.1768 | 0.5773 |        4 |
| blind    | S3       | granite41_8b      | 414 | 1.2671 | 0.6377 |        8 |
| blind    | S3       | llama31_8b        | 414 | 0.9338 | 0.186  |        8 |
| blind    | S3       | qwen3_14b         | 414 | 2.093  | 0.4831 |       14 |
| blind    | S3       | mistral_small_24b | 414 | 0.957  | 0.5749 |       24 |
| blind    | S3       | granite41_30b     | 414 | 0.8812 | 0.7657 |       30 |
| blind    | S3       | gemma4_31b        | 414 | 0.3647 | 0.744  |       31 |
| tracker  | DC       | qwen3_4b          | 414 | 0.0374 | 0.9251 |        4 |
| tracker  | DC       | granite41_8b      | 414 | 0.0338 | 0.9396 |        8 |
| tracker  | DC       | llama31_8b        | 414 | 0.0254 | 0.9493 |        8 |
| tracker  | DC       | qwen3_14b         | 414 | 0.0254 | 0.9493 |       14 |
| tracker  | DC       | mistral_small_24b | 414 | 0.0254 | 0.9493 |       24 |
| tracker  | DC       | granite41_30b     | 414 | 0.0435 | 0.9203 |       30 |
| tracker  | DC       | gemma4_31b        | 414 | 0.0254 | 0.9493 |       31 |
| tracker  | S3       | qwen3_4b          | 414 | 1.5473 | 0.6353 |        4 |
| tracker  | S3       | granite41_8b      | 414 | 0.7691 | 0.7971 |        8 |
| tracker  | S3       | llama31_8b        | 414 | 1.613  | 0.3986 |        8 |
| tracker  | S3       | qwen3_14b         | 414 | 1.1329 | 0.7222 |       14 |
| tracker  | S3       | mistral_small_24b | 414 | 0.8394 | 0.7005 |       24 |
| tracker  | S3       | granite41_30b     | 414 | 0.6176 | 0.8237 |       30 |
| tracker  | S3       | gemma4_31b        | 414 | 0.0819 | 0.9662 |       31 |
| withheld | DC       | qwen3_4b          | 414 | 0.3442 | 0.3116 |        4 |
| withheld | DC       | granite41_8b      | 414 | 0.3442 | 0.3116 |        8 |
| withheld | DC       | llama31_8b        | 414 | 0.3442 | 0.3116 |        8 |
| withheld | DC       | qwen3_14b         | 414 | 0.3442 | 0.3116 |       14 |
| withheld | DC       | mistral_small_24b | 414 | 0.3442 | 0.3116 |       24 |
| withheld | DC       | granite41_30b     | 414 | 0.3442 | 0.3116 |       30 |
| withheld | DC       | gemma4_31b        | 414 | 0.3442 | 0.3116 |       31 |
| withheld | S3       | qwen3_4b          | 414 | 1.8065 | 0.558  |        4 |
| withheld | S3       | granite41_8b      | 414 | 1.151  | 0.6377 |        8 |
| withheld | S3       | llama31_8b        | 414 | 1.2225 | 0.2754 |        8 |
| withheld | S3       | qwen3_14b         | 414 | 2.1423 | 0.5193 |       14 |
| withheld | S3       | mistral_small_24b | 414 | 1.6302 | 0.5338 |       24 |
| withheld | S3       | granite41_30b     | 414 | 0.9275 | 0.7609 |       30 |
| withheld | S3       | gemma4_31b        | 414 | 0.2908 | 0.7633 |       31 |

- D7 blind: S3[granite41_30b] − DC loss on 414 matched cases: 0.537 [0.252, 0.826], sign-flip p = 0.0004
- D7 tracker: S3[granite41_30b] − DC loss on 414 matched cases: 0.587 [0.366, 0.845], sign-flip p = 9.999e-05
- D7 withheld: S3[granite41_30b] − DC loss on 414 matched cases: 0.583 [0.296, 0.881], sign-flip p = 0.0003
