"""
BaseAgent: shared OpenAI client, JSON call helper, RAG retrieval, and logging.
All five specialized agents inherit from this class.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from config import settings

logger = logging.getLogger(__name__)


class BaseAgent:
    """Common foundation for all taint-analyst agents."""

    name: str = "BaseAgent"

    def __init__(self, model: Optional[str] = None, rag_store=None):
        self.model = model or settings.openai_model
        self.client = AsyncOpenAI(
            api_key=settings.openai_api_key or None,
            base_url=settings.openai_base_url,
            organization=settings.openai_organization,
            project=settings.openai_project,
        )
        self.rag_store = rag_store

    # ------------------------------------------------------------------
    # Core LLM call — always requests JSON output
    # ------------------------------------------------------------------

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=20),
    )
    async def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Call the LLM and return parsed JSON.
        Uses response_format json_object to enforce structured output.
        """
        logger.debug(f"[{self.name}] Calling LLM — model={self.model}")

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        if response_format:
            kwargs["response_format"] = response_format
        else:
            kwargs["response_format"] = {"type": "json_object"}

        response = await self.client.chat.completions.create(**kwargs)
        raw = response.choices[0].message.content

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error(f"[{self.name}] JSON parse failure: {exc}\nRaw: {raw[:500]}")
            raise

    # ------------------------------------------------------------------
    # RAG retrieval — optional, used when rag_store is available
    # ------------------------------------------------------------------

    async def retrieve_references(self, query: str, top_k: int = 3) -> str:
        """Return relevant reference document chunks for the query."""
        if self.rag_store is None:
            return ""
        chunks = await self.rag_store.query(query, top_k=top_k)
        if not chunks:
            return ""
        formatted = "\n\n---\n\n".join(
            f"[Source: {c['source']} | Section: {c['section']}]\n{c['text']}"
            for c in chunks
        )
        return f"\n\n## Reference Material\n\n{formatted}\n"

    # ------------------------------------------------------------------
    # Utility: chunk large file content to stay within token budget
    # ------------------------------------------------------------------

    @staticmethod
    def chunk_content(content: str, max_chars: int = 24_000) -> list[str]:
        """
        Split content into chunks of at most max_chars characters.
        Splits on newlines to avoid cutting mid-line.
        """
        if len(content) <= max_chars:
            return [content]

        chunks = []
        lines = content.splitlines(keepends=True)
        current = []
        current_len = 0

        for line in lines:
            if current_len + len(line) > max_chars and current:
                chunks.append("".join(current))
                current = [line]
                current_len = len(line)
            else:
                current.append(line)
                current_len += len(line)

        if current:
            chunks.append("".join(current))

        return chunks
