# Metric Definitions for the DeepCTI Experiment Section

## Semantic Cosine Similarity

We compute embedding-based cosine similarity between the generated final mitigation target and the reference mitigation target. Because cosine similarity depends on the embedding manifold, we report results using three embedding models: all-MiniLM-L6-v2, all-mpnet-base-v2, and e5-base-v2. This metric is continuous and is reported directly; it is not an F1 score.

## Thresholded Match F1

To compute F1, we convert cosine similarity into a binary match decision using thresholds tau_match = {0.50, 0.60, 0.70}. A generated-reference pair is considered a positive match if its similarity is above the threshold. To make precision meaningful, we also create negative-control pairs by comparing generated outputs against the wrong case reference. True positives are correct case pairs above threshold, false negatives are correct case pairs below threshold, and false positives are negative-control pairs above threshold.

## Retrieval Sufficiency

For each case, candidate evidence chunks are ranked by semantic similarity to the analyst question/current state. We consider up to Top-K chunks and select chunks until the normalized cumulative similarity exceeds Top-P. If Top-K does not reach Top-P, the run is marked as retrieval-insufficient. This operationalizes the stopping condition discussed in the formulation.

## Iteration Distribution

We report mean, median, standard deviation, and distribution of the number of selected evidence chunks/state transitions. This shows whether DeepCTI performs variable-depth deep research rather than a fixed one-step generation process.

## Model-Agnostic Robustness

We run the same modes across several local LLMs and report whether iterative DeepCTI improves over one-shot and no-memory settings consistently across models.
