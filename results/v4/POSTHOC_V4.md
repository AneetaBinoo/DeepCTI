# prereg-v4 POST HOC — H18 corrected analyses (DEVIATIONS D25)

Models with both X6 and X6C: 8 (gemma4_31b, granite41_30b, granite41_8b, llama31_8b, mistral_medium_128b, mistral_small_24b, qwen3_14b, qwen3_4b).
Share of vendor decoys implying a different status: 0.761

| analysis                   | system      |   share_seen |   n |   cves |   loss_decoy |   loss_clean |    diff |      lo |      hi |   p_signflip |
|:---------------------------|:------------|-------------:|----:|-------:|-------------:|-------------:|--------:|--------:|--------:|-------------:|
| X6 vs X6C (same code)      | DC          |        0.115 | 832 |     38 |       0.0409 |       0.0415 | -0.0006 | -0.0019 |  0      |       1      |
| exposed before decision    | DC          |      nan     |  96 |      3 |       0.0208 |       0.026  | -0.0052 | -0.0156 |  0      |       1      |
| decoy implies other status | DC          |      nan     | 744 |     38 |       0.041  |       0.041  |  0      |  0      |  0      |       1      |
| ecosystem=deb-ubuntu       | DC          |      nan     | 464 |     27 |       0      |       0      |  0      |  0      |  0      |       1      |
| ecosystem=vendor           | DC          |      nan     | 368 |     11 |       0.0924 |       0.0938 | -0.0014 | -0.0043 |  0      |       1      |
| X6 vs X6C (same code)      | DC_noverify |        0.115 | 832 |     38 |       0.0204 |       0.0204 |  0      |  0      |  0      |       1      |
| exposed before decision    | DC_noverify |      nan     |  96 |      3 |       0.0625 |       0.0625 |  0      |  0      |  0      |       1      |
| decoy implies other status | DC_noverify |      nan     | 744 |     38 |       0.0188 |       0.0188 |  0      |  0      |  0      |       1      |
| ecosystem=deb-ubuntu       | DC_noverify |      nan     | 464 |     27 |       0      |       0      |  0      |  0      |  0      |       1      |
| ecosystem=vendor           | DC_noverify |      nan     | 368 |     11 |       0.0462 |       0.0462 |  0      |  0      |  0      |       1      |
| X6 vs X6C (same code)      | S3          |        0.106 | 832 |     38 |       1.7976 |       1.8145 | -0.0169 | -0.1307 |  0.1006 |       0.8212 |
| exposed before decision    | S3          |      nan     |  88 |     13 |       1.0932 |       1.3534 | -0.2602 | -0.4775 | -0.0254 |       0.0281 |
| decoy implies other status | S3          |      nan     | 744 |     38 |       1.7089 |       1.6864 |  0.0224 | -0.0832 |  0.1297 |       0.9196 |
| ecosystem=deb-ubuntu       | S3          |      nan     | 464 |     27 |       1.7472 |       1.7675 | -0.0203 | -0.1595 |  0.1277 |       0.8085 |
| ecosystem=vendor           | S3          |      nan     | 368 |     11 |       1.8611 |       1.8739 | -0.0128 | -0.191  |  0.1756 |       0.9571 |
