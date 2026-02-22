from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
from openai import AsyncOpenAI

from config import settings

logger = logging.getLogger(__name__)

CHUNK_CHAR_LIMIT = 1800
CHUNK_OVERLAP = 200


@dataclass
class RAGChunk:
    source: str
    section: str
    text: str
    embedding: np.ndarray | None = None


class RAGStore:
    """Small local vector store backed by OpenAI embeddings."""

    def __init__(self, docs_path: Path):
        self.docs_path = docs_path
        self.client = AsyncOpenAI(
            api_key=settings.openai_api_key or None,
            base_url=settings.openai_base_url,
            organization=settings.openai_organization,
            project=settings.openai_project,
        )
        self.chunks: List[RAGChunk] = []
        self._ready = False

    async def initialize(self) -> None:
        files = sorted(self.docs_path.glob("**/*"))
        doc_files = [p for p in files if p.is_file() and p.suffix.lower() in {".md", ".txt"}]
        if not doc_files:
            logger.info("[RAGStore] No docs found at %s", self.docs_path)
            self._ready = True
            return

        for path in doc_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            self.chunks.extend(self._chunk_document(path, text))

        if not self.chunks:
            self._ready = True
            return

        if not settings.openai_api_key:
            logger.warning("[RAGStore] OPENAI_API_KEY missing; using lexical fallback retrieval only")
            self._ready = True
            return

        try:
            await self._embed_chunks()
        except Exception as exc:
            logger.warning("[RAGStore] Embedding build failed; using lexical fallback: %s", exc)
        self._ready = True
        logger.info("[RAGStore] Loaded %d chunks from %d files", len(self.chunks), len(doc_files))

    async def query(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not self._ready:
            await self.initialize()
        if not self.chunks:
            return []

        if self.chunks[0].embedding is None:
            return self._lexical_query(query, top_k=top_k)

        query_embedding = await self._embed_text(query)
        q_norm = np.linalg.norm(query_embedding) or 1.0

        scored: List[tuple[float, RAGChunk]] = []
        for chunk in self.chunks:
            if chunk.embedding is None:
                continue
            c_norm = np.linalg.norm(chunk.embedding) or 1.0
            score = float(np.dot(query_embedding, chunk.embedding) / (q_norm * c_norm))
            scored.append((score, chunk))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                "source": s.source,
                "section": s.section,
                "text": s.text,
                "score": round(score, 6),
            }
            for score, s in scored[:top_k]
        ]

    def _chunk_document(self, path: Path, text: str) -> List[RAGChunk]:
        section = "General"
        chunks: List[RAGChunk] = []
        current = ""

        for line in text.splitlines():
            if line.startswith("#"):
                if current.strip():
                    chunks.extend(self._sliding_chunks(path.name, section, current))
                section = line.lstrip("# ").strip() or section
                current = ""
                continue
            current += line + "\n"

        if current.strip():
            chunks.extend(self._sliding_chunks(path.name, section, current))
        return chunks

    def _sliding_chunks(self, source: str, section: str, text: str) -> List[RAGChunk]:
        if len(text) <= CHUNK_CHAR_LIMIT:
            return [RAGChunk(source=source, section=section, text=text.strip())]

        result: List[RAGChunk] = []
        start = 0
        while start < len(text):
            end = min(start + CHUNK_CHAR_LIMIT, len(text))
            block = text[start:end].strip()
            if block:
                result.append(RAGChunk(source=source, section=section, text=block))
            if end >= len(text):
                break
            start = max(end - CHUNK_OVERLAP, start + 1)
        return result

    async def _embed_chunks(self) -> None:
        batch_size = 64
        for i in range(0, len(self.chunks), batch_size):
            batch = self.chunks[i : i + batch_size]
            inputs = [chunk.text for chunk in batch]
            response = await self.client.embeddings.create(
                model=settings.openai_embedding_model,
                input=inputs,
            )
            for chunk, emb in zip(batch, response.data):
                chunk.embedding = np.array(emb.embedding, dtype=np.float32)

    async def _embed_text(self, text: str) -> np.ndarray:
        response = await self.client.embeddings.create(
            model=settings.openai_embedding_model,
            input=[text],
        )
        return np.array(response.data[0].embedding, dtype=np.float32)

    def _lexical_query(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query_tokens = self._tokenize(query)
        scored: List[tuple[float, RAGChunk]] = []

        for chunk in self.chunks:
            chunk_tokens = self._tokenize(chunk.text)
            overlap = len(query_tokens.intersection(chunk_tokens))
            score = overlap / (math.sqrt(len(chunk_tokens) + 1))
            scored.append((score, chunk))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                "source": c.source,
                "section": c.section,
                "text": c.text,
                "score": round(score, 6),
            }
            for score, c in scored[:top_k]
            if score > 0
        ]

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        words = [w.strip(".,:;()[]{}<>\"'").lower() for w in text.split()]
        return {w for w in words if len(w) > 2}
