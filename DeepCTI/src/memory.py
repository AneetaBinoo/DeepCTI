from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import hashlib
import chromadb
from chromadb.utils import embedding_functions


@dataclass
class EvidenceItem:
    evidence_id: str
    text: str
    source: str
    metadata: Dict[str, Any]


class EvidenceStore:
    def __init__(self, persist_dir: str, collection_name: str):
        print(f"[CHROMA] Initializing PersistentClient at: {persist_dir}")
        self.client = chromadb.PersistentClient(path=persist_dir)

        print("[CHROMA] Loading embedding model: all-MiniLM-L6-v2 (first run may download from HF)")
        embedder = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

        self.col = self.client.get_or_create_collection(name=collection_name, embedding_function=embedder)
        print(f"[CHROMA] Collection ready: {collection_name}")

    @staticmethod
    def _make_id(source: str, text: str, extra: str = "") -> str:
        h = hashlib.sha256((source + "|" + extra + "|" + text).encode("utf-8")).hexdigest()[:16]
        return f"ev_{h}"

    def add(self, text: str, source: str, metadata: Dict[str, Any], extra: str = "") -> EvidenceItem:
        text = (text or "").strip()
        if not text:
            raise ValueError("Cannot add empty evidence text")
        ev_id = self._make_id(source, text, extra=extra)
        self.col.upsert(ids=[ev_id], documents=[text], metadatas=[{"source": source, **metadata}])
        return EvidenceItem(evidence_id=ev_id, text=text, source=source, metadata={"source": source, **metadata})

    def query(self, query_text: str, k: int = 5, where: Optional[Dict[str, Any]] = None) -> List[EvidenceItem]:
        print(f"[CHROMA] Query start | k={k} | where={where}")
        kwargs = {"query_texts": [query_text], "n_results": k}
        if where:
            kwargs["where"] = where
        res = self.col.query(**kwargs)
        ids = (res.get("ids") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        items: List[EvidenceItem] = []
        for ev_id, doc, meta in zip(ids, docs, metas):
            meta = meta or {}
            items.append(EvidenceItem(evidence_id=ev_id, text=doc or "", source=meta.get("source", "unknown"), metadata=meta))
        print(f"[CHROMA] Query done | returned={len(items)}")
        return items

    def get_items(self, evidence_ids: List[str]) -> List[EvidenceItem]:
        if not evidence_ids:
            return []
        res = self.col.get(ids=evidence_ids)
        ids = res.get("ids") or []
        docs = res.get("documents") or []
        metas = res.get("metadatas") or []
        out: List[EvidenceItem] = []
        for ev_id, doc, meta in zip(ids, docs, metas):
            meta = meta or {}
            out.append(EvidenceItem(evidence_id=ev_id, text=doc or "", source=meta.get("source", "unknown"), metadata=meta))
        return out

    def exists(self, evidence_id: str) -> bool:
        res = self.col.get(ids=[evidence_id])
        ids = res.get("ids") or []
        return len(ids) > 0