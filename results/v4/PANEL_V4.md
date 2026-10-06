# prereg-v4 descriptive panel completion (scripts/paper/analyze_v4_panel.py)

Descriptive only (prereg/PREREGISTRATION_V4.md §2); not part of any hypothesis family.

## D1 E2 (all models, incl. GLM-4.5-Air)

| arm      | system   | model               |   n |   loss |    acc |    DER |
|:---------|:---------|:--------------------|----:|-------:|-------:|-------:|
| tracker  | DC       | gemma4_31b          | 453 | 0      | 1      | 0      |
| tracker  | DC       | glm45_air           | 453 | 0      | 1      | 0      |
| tracker  | DC       | granite41_30b       | 453 | 0      | 1      | 0      |
| tracker  | DC       | granite41_8b        | 453 | 0      | 1      | 0      |
| tracker  | DC       | llama31_8b          | 453 | 0      | 1      | 0      |
| tracker  | DC       | mistral_medium_128b | 453 | 0      | 1      | 0      |
| tracker  | DC       | mistral_small_24b   | 453 | 0      | 1      | 0      |
| tracker  | DC       | nemotron_super_49b  | 453 | 0      | 1      | 0      |
| tracker  | DC       | qwen3_14b           | 453 | 0      | 1      | 0      |
| tracker  | DC       | qwen3_4b            | 453 | 0      | 1      | 0      |
| tracker  | S2       | gemma4_31b          | 453 | 0.0525 | 0.9625 | 0.0143 |
| tracker  | S2       | glm45_air           | 453 | 2.0651 | 0.7196 | 0.6571 |
| tracker  | S2       | granite41_30b       | 453 | 0.6031 | 0.8587 | 0.1857 |
| tracker  | S2       | granite41_8b        | 453 | 2.3989 | 0.6998 | 0.7714 |
| tracker  | S2       | llama31_8b          | 453 | 2.7581 | 0.4062 | 0.8714 |
| tracker  | S2       | mistral_medium_128b | 453 | 0.1764 | 0.8874 | 0.0429 |
| tracker  | S2       | mistral_small_24b   | 453 | 2.3876 | 0.6865 | 0.7571 |
| tracker  | S2       | nemotron_super_49b  | 453 | 1.6146 | 0.7395 | 0.5143 |
| tracker  | S2       | qwen3_14b           | 453 | 1.2113 | 0.8322 | 0.3857 |
| tracker  | S2       | qwen3_4b            | 453 | 2.4    | 0.6799 | 0.7643 |
| tracker  | S3       | gemma4_31b          | 453 | 0.177  | 0.9801 | 0.0571 |
| tracker  | S3       | glm45_air           | 453 | 0.9662 | 0.8124 | 0.3    |
| tracker  | S3       | granite41_30b       | 453 | 0.4397 | 0.8918 | 0.1286 |
| tracker  | S3       | granite41_8b        | 453 | 0.9563 | 0.8322 | 0.3    |
| tracker  | S3       | llama31_8b          | 453 | 1.7711 | 0.4702 | 0.5214 |
| tracker  | S3       | mistral_medium_128b | 453 | 0.4093 | 0.9227 | 0.1286 |
| tracker  | S3       | mistral_small_24b   | 453 | 0.6393 | 0.8675 | 0.2    |
| tracker  | S3       | nemotron_super_49b  | 453 | 1.7139 | 0.2406 | 0.4286 |
| tracker  | S3       | qwen3_14b           | 453 | 0.3464 | 0.9272 | 0.1    |
| tracker  | S3       | qwen3_4b            | 453 | 2.6364 | 0.6733 | 0.8429 |
| withheld | DC       | gemma4_31b          | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | glm45_air           | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | granite41_30b       | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | granite41_8b        | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | llama31_8b          | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | mistral_medium_128b | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | mistral_small_24b   | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | nemotron_super_49b  | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | qwen3_14b           | 453 | 0.0671 | 0.6733 | 0      |
| withheld | DC       | qwen3_4b            | 453 | 0.0671 | 0.6733 | 0      |
| withheld | S2       | gemma4_31b          | 453 | 0.2711 | 0.8344 | 0.0571 |
| withheld | S2       | glm45_air           | 453 | 2.4139 | 0.4128 | 0.7143 |
| withheld | S2       | granite41_30b       | 453 | 2.2731 | 0.6291 | 0.7214 |
| withheld | S2       | granite41_8b        | 453 | 2.5673 | 0.6026 | 0.8214 |
| withheld | S2       | llama31_8b          | 453 | 2.7214 | 0.4084 | 0.8571 |
| withheld | S2       | mistral_medium_128b | 453 | 1.8208 | 0.5872 | 0.5571 |
| withheld | S2       | mistral_small_24b   | 453 | 2.4903 | 0.5254 | 0.7714 |
| withheld | S2       | nemotron_super_49b  | 453 | 2.3623 | 0.4194 | 0.7357 |
| withheld | S2       | qwen3_14b           | 453 | 2.4106 | 0.4525 | 0.7571 |
| withheld | S2       | qwen3_4b            | 453 | 2.4786 | 0.5519 | 0.7643 |
| withheld | S3       | gemma4_31b          | 453 | 0.7088 | 0.7241 | 0.1929 |
| withheld | S3       | glm45_air           | 453 | 1.4806 | 0.5408 | 0.4286 |
| withheld | S3       | granite41_30b       | 453 | 0.645  | 0.4283 | 0.1214 |
| withheld | S3       | granite41_8b        | 453 | 1.5993 | 0.6049 | 0.4714 |
| withheld | S3       | llama31_8b          | 453 | 2.4424 | 0.3753 | 0.7286 |
| withheld | S3       | mistral_medium_128b | 453 | 0.8552 | 0.6998 | 0.25   |
| withheld | S3       | mistral_small_24b   | 453 | 1.0971 | 0.6004 | 0.3071 |
| withheld | S3       | nemotron_super_49b  | 453 | 1.6974 | 0.234  | 0.4214 |
| withheld | S3       | qwen3_14b           | 453 | 2.5124 | 0.426  | 0.7857 |
| withheld | S3       | qwen3_4b            | 453 | 1.5523 | 0.5453 | 0.4214 |

## D7 X2 (all models, incl. GLM-4.5-Air)

| arm      | system   | model               |   n |   loss |    acc |    DER |
|:---------|:---------|:--------------------|----:|-------:|-------:|-------:|
| blind    | DC       | gemma4_31b          | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | glm45_air           | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | granite41_30b       | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | granite41_8b        | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | llama31_8b          | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | mistral_medium_128b | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | mistral_small_24b   | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | qwen3_14b           | 414 | 0.3442 | 0.3116 | 0      |
| blind    | DC       | qwen3_4b            | 414 | 0.3442 | 0.3116 | 0      |
| blind    | S2       | gemma4_31b          | 414 | 0.2205 | 0.8164 | 0.0203 |
| blind    | S2       | glm45_air           | 414 | 0.5425 | 0.6208 | 0.0743 |
| blind    | S2       | granite41_30b       | 414 | 1.3041 | 0.7053 | 0.3378 |
| blind    | S2       | granite41_8b        | 414 | 1.4005 | 0.587  | 0.3243 |
| blind    | S2       | llama31_8b          | 414 | 1.9353 | 0.5169 | 0.4865 |
| blind    | S2       | mistral_medium_128b | 414 | 1.0928 | 0.7126 | 0.277  |
| blind    | S2       | mistral_small_24b   | 414 | 0.7737 | 0.6329 | 0.1419 |
| blind    | S2       | qwen3_14b           | 414 | 1.349  | 0.5604 | 0.3176 |
| blind    | S2       | qwen3_4b            | 414 | 0.5836 | 0.6401 | 0.0743 |
| blind    | S3       | gemma4_31b          | 414 | 0.3647 | 0.744  | 0.0676 |
| blind    | S3       | glm45_air           | 414 | 0.9343 | 0.6691 | 0.2162 |
| blind    | S3       | granite41_30b       | 414 | 0.8812 | 0.7657 | 0.2162 |
| blind    | S3       | granite41_8b        | 414 | 1.2671 | 0.6377 | 0.3041 |
| blind    | S3       | llama31_8b          | 414 | 0.9338 | 0.186  | 0.1351 |
| blind    | S3       | mistral_medium_128b | 414 | 0.5357 | 0.7585 | 0.1149 |
| blind    | S3       | mistral_small_24b   | 414 | 0.957  | 0.5749 | 0.2095 |
| blind    | S3       | qwen3_14b           | 414 | 2.093  | 0.4831 | 0.5405 |
| blind    | S3       | qwen3_4b            | 414 | 1.1768 | 0.5773 | 0.2635 |
| tracker  | DC       | gemma4_31b          | 414 | 0.0254 | 0.9493 | 0      |
| tracker  | DC       | glm45_air           | 414 | 0.0181 | 0.9638 | 0      |
| tracker  | DC       | granite41_30b       | 414 | 0.0435 | 0.9203 | 0      |
| tracker  | DC       | granite41_8b        | 414 | 0.0338 | 0.9396 | 0      |
| tracker  | DC       | llama31_8b          | 414 | 0.0254 | 0.9493 | 0      |
| tracker  | DC       | mistral_medium_128b | 414 | 0.0205 | 0.9589 | 0      |
| tracker  | DC       | mistral_small_24b   | 414 | 0.0254 | 0.9493 | 0      |
| tracker  | DC       | qwen3_14b           | 414 | 0.0254 | 0.9493 | 0      |
| tracker  | DC       | qwen3_4b            | 414 | 0.0374 | 0.9251 | 0      |
| tracker  | S2       | gemma4_31b          | 414 | 0.0244 | 0.9493 | 0      |
| tracker  | S2       | glm45_air           | 414 | 1.4763 | 0.6812 | 0.3784 |
| tracker  | S2       | granite41_30b       | 414 | 0.3469 | 0.8502 | 0.0743 |
| tracker  | S2       | granite41_8b        | 414 | 2.9425 | 0.5121 | 0.7838 |
| tracker  | S2       | llama31_8b          | 414 | 2.5118 | 0.4589 | 0.6419 |
| tracker  | S2       | mistral_medium_128b | 414 | 0.3036 | 0.8527 | 0.0608 |
| tracker  | S2       | mistral_small_24b   | 414 | 2.3894 | 0.5797 | 0.6216 |
| tracker  | S2       | qwen3_14b           | 414 | 0.8138 | 0.715  | 0.2027 |
| tracker  | S2       | qwen3_4b            | 414 | 1.563  | 0.558  | 0.3581 |
| tracker  | S3       | gemma4_31b          | 414 | 0.0819 | 0.9662 | 0.0203 |
| tracker  | S3       | glm45_air           | 414 | 0.8384 | 0.7609 | 0.2095 |
| tracker  | S3       | granite41_30b       | 414 | 0.6176 | 0.8237 | 0.1486 |
| tracker  | S3       | granite41_8b        | 414 | 0.7691 | 0.7971 | 0.1892 |
| tracker  | S3       | llama31_8b          | 414 | 1.613  | 0.3986 | 0.3649 |
| tracker  | S3       | mistral_medium_128b | 414 | 0.2109 | 0.9106 | 0.0473 |
| tracker  | S3       | mistral_small_24b   | 414 | 0.8394 | 0.7005 | 0.1959 |
| tracker  | S3       | qwen3_14b           | 414 | 1.1329 | 0.7222 | 0.2838 |
| tracker  | S3       | qwen3_4b            | 414 | 1.5473 | 0.6353 | 0.3851 |
| withheld | DC       | gemma4_31b          | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | glm45_air           | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | granite41_30b       | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | granite41_8b        | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | llama31_8b          | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | mistral_medium_128b | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | mistral_small_24b   | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | qwen3_14b           | 414 | 0.3442 | 0.3116 | 0      |
| withheld | DC       | qwen3_4b            | 414 | 0.3442 | 0.3116 | 0      |
| withheld | S2       | gemma4_31b          | 414 | 0.1372 | 0.8309 | 0      |
| withheld | S2       | glm45_air           | 414 | 2.2845 | 0.43   | 0.5676 |
| withheld | S2       | granite41_30b       | 414 | 2.2271 | 0.6063 | 0.6014 |
| withheld | S2       | granite41_8b        | 414 | 3.0304 | 0.442  | 0.8041 |
| withheld | S2       | llama31_8b          | 414 | 2.9307 | 0.4348 | 0.777  |
| withheld | S2       | mistral_medium_128b | 414 | 0.5821 | 0.756  | 0.1351 |
| withheld | S2       | mistral_small_24b   | 414 | 2.9123 | 0.4275 | 0.7568 |
| withheld | S2       | qwen3_14b           | 414 | 2.0348 | 0.5193 | 0.5473 |
| withheld | S2       | qwen3_4b            | 414 | 2.7493 | 0.4179 | 0.6892 |
| withheld | S3       | gemma4_31b          | 414 | 0.2908 | 0.7633 | 0.0473 |
| withheld | S3       | glm45_air           | 414 | 0.9647 | 0.6618 | 0.223  |
| withheld | S3       | granite41_30b       | 414 | 0.9275 | 0.7609 | 0.2297 |
| withheld | S3       | granite41_8b        | 414 | 1.151  | 0.6377 | 0.2703 |
| withheld | S3       | llama31_8b          | 414 | 1.2225 | 0.2754 | 0.2432 |
| withheld | S3       | mistral_medium_128b | 414 | 0.6459 | 0.7585 | 0.1486 |
| withheld | S3       | mistral_small_24b   | 414 | 1.6302 | 0.5338 | 0.4054 |
| withheld | S3       | qwen3_14b           | 414 | 2.1423 | 0.5193 | 0.5608 |
| withheld | S3       | qwen3_4b            | 414 | 1.8065 | 0.558  | 0.4527 |

## D7 X5 drift, GLM-4.5-Air

| kind               | system   |   n |   loss |   acc |      DER |
|:-------------------|:---------|----:|-------:|------:|---------:|
| remove             | DC       |  40 | 0.1125 | 0.825 | nan      |
| remove             | DCv21    |  40 | 0.1125 | 0.825 | nan      |
| remove             | S2       |  40 | 0.5625 | 0     | nan      |
| remove             | S3       |  40 | 0.395  | 0.525 | nan      |
| rollback           | DC       |  40 | 0.025  | 0.95  |   0      |
| rollback           | DCv21    |  40 | 0.025  | 0.95  |   0      |
| rollback           | S2       |  40 | 1.0875 | 0.725 |   0.1    |
| rollback           | S3       |  40 | 5.0125 | 0.475 |   0.5    |
| upgrade_no_restart | DC       |  40 | 5.055  | 0.3   |   0.6061 |
| upgrade_no_restart | DCv21    |  40 | 0.025  | 0.95  |   0      |
| upgrade_no_restart | S2       |  40 | 0.1475 | 0.775 |   0      |
| upgrade_no_restart | S3       |  40 | 3.53   | 0.6   |   0.4242 |
| upgrade_restart    | DC       |  40 | 0.0125 | 0.975 | nan      |
| upgrade_restart    | DCv21    |  40 | 0.125  | 0.75  | nan      |
| upgrade_restart    | S2       |  40 | 0.4625 | 0.375 | nan      |
| upgrade_restart    | S3       |  40 | 0.24   | 0.5   | nan      |

## D1 E5 (D3 security), Mistral-Medium-128B: share of episodes with an unauthorized disruptive execution

| system      | policy   |   n |   udar |
|:------------|:---------|----:|-------:|
| DC          | P2       | 384 | 0.0208 |
| DC          | P3       | 384 | 0.0208 |
| DC_noverify | P3       | 384 | 0.0208 |
| DC_q2       | P3       | 384 | 0.0208 |
| S3          | P0       | 384 | 0.0286 |
| S3          | P1       | 768 | 0.026  |
| S3          | P3       | 384 | 0      |

## D1 E9 pass^k (T = 0.7), all models

| model               | system   |   cases |   pass_k |   seeds |
|:--------------------|:---------|--------:|---------:|--------:|
| gemma4_31b          | DC       |     150 |   1      |       5 |
| gemma4_31b          | S3       |     150 |   0.98   |       5 |
| granite41_30b       | DC       |     150 |   1      |       5 |
| granite41_30b       | S3       |     150 |   0.8867 |       5 |
| granite41_8b        | DC       |     150 |   1      |       5 |
| granite41_8b        | S3       |     150 |   0.6    |       5 |
| llama31_8b          | DC       |     150 |   1      |       5 |
| llama31_8b          | S3       |     150 |   0.08   |       5 |
| mistral_medium_128b | DC       |     150 |   1      |       5 |
| mistral_medium_128b | S3       |     150 |   0.7933 |       5 |
| mistral_small_24b   | DC       |     150 |   1      |       5 |
| mistral_small_24b   | S3       |     150 |   0.58   |       5 |
| nemotron_super_49b  | DC       |     150 |   1      |       5 |
| nemotron_super_49b  | S3       |     150 |   0      |       5 |
| qwen3_14b           | DC       |     150 |   1      |       5 |
| qwen3_14b           | S3       |     150 |   0.88   |       5 |
| qwen3_4b            | DC       |     150 |   1      |       5 |
| qwen3_4b            | S3       |     150 |   0.7133 |       5 |

## D7 X2V (vendor cases, fixed verifier D21), pooled over 8 models

| arm      | system      |   n |   loss |    acc |   DER |
|:---------|:------------|----:|-------:|-------:|------:|
| blind    | DC          | 672 | 0.3512 | 0.2976 |     0 |
| blind    | DC_noverify | 672 | 0.3512 | 0.2976 |     0 |
| blind    | DCv21       | 672 | 0.3512 | 0.2976 |     0 |
| blind    | S1p         |  84 | 0.3512 | 0.2976 |     0 |
| tracker  | DC          | 672 | 0.1131 | 0.7738 |     0 |
| tracker  | DC_noverify | 672 | 0.0838 | 0.8333 |     0 |
| tracker  | DCv21       | 672 | 0.1443 | 0.7113 |     0 |
| tracker  | S1p         |  84 | 0.3512 | 0.2976 |     0 |
| withheld | DC          | 672 | 0.3512 | 0.2976 |     0 |
| withheld | DC_noverify | 672 | 0.3512 | 0.2976 |     0 |
| withheld | DCv21       | 672 | 0.3512 | 0.2976 |     0 |
| withheld | S1p         |  84 | 0.3512 | 0.2976 |     0 |

