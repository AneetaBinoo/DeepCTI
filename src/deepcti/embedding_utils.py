from __future__ import annotations
from functools import lru_cache
from typing import List
import numpy as np

EMBEDDING_MODELS = [
    "sentence-transformers/all-MiniLM-L6-v2",
    "sentence-transformers/all-mpnet-base-v2",
    "intfloat/e5-base-v2",
]

@lru_cache(maxsize=4)
def get_model(name: str):
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(name)


def _prep_for_e5(texts: List[str], is_query: bool) -> List[str]:
    # E5 models are trained with query:/passage: prefixes.
    if "e5" in " ".join(texts[:1]).lower():
        return texts
    return texts


def encode_texts(model_name: str, texts: List[str], is_query: bool = False) -> np.ndarray:
    model = get_model(model_name)
    if "e5" in model_name.lower():
        pref = "query: " if is_query else "passage: "
        texts = [pref + (t or "") for t in texts]
    emb = model.encode(texts, convert_to_numpy=True, normalize_embeddings=True, show_progress_bar=False)
    return emb


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-12))


def batch_cosine(model_name: str, left: List[str], right: List[str]) -> List[float]:
    A = encode_texts(model_name, left, is_query=False)
    B = encode_texts(model_name, right, is_query=False)
    return [cosine(a, b) for a, b in zip(A, B)]
