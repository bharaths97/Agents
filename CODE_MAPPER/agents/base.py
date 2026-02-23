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
        self._token_usage: Dict[str, int] = {
            "calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cached_tokens": 0,
            "reasoning_tokens": 0,
        }

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

        # Reasoning models (o1, o3, gpt-5 family) only support default temperature
        _reasoning_prefixes = ("o1", "o3", "gpt-5")
        _skip_temperature = any(self.model.startswith(p) for p in _reasoning_prefixes)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if not _skip_temperature:
            kwargs["temperature"] = temperature

        if response_format:
            kwargs["response_format"] = response_format
        else:
            kwargs["response_format"] = {"type": "json_object"}

        response = await self.client.chat.completions.create(**kwargs)
        self._record_token_usage(response)
        raw = response.choices[0].message.content

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error(f"[{self.name}] JSON parse failure: {exc}\nRaw: {raw[:500]}")
            raise

    def get_token_usage(self) -> Dict[str, Any]:
        usage = dict(self._token_usage)
        usage["agent_name"] = self.name
        usage["model"] = self.model
        return usage

    def _record_token_usage(self, response: Any) -> None:
        usage_obj = getattr(response, "usage", None)
        if usage_obj is None and isinstance(response, dict):
            usage_obj = response.get("usage")

        self._token_usage["calls"] += 1
        if usage_obj is None:
            return

        self._token_usage["prompt_tokens"] += self._int_usage_field(usage_obj, "prompt_tokens")
        self._token_usage["completion_tokens"] += self._int_usage_field(usage_obj, "completion_tokens")
        self._token_usage["total_tokens"] += self._int_usage_field(usage_obj, "total_tokens")

        prompt_details = self._usage_subfield(usage_obj, "prompt_tokens_details")
        completion_details = self._usage_subfield(usage_obj, "completion_tokens_details")
        if prompt_details is not None:
            self._token_usage["cached_tokens"] += self._int_usage_field(prompt_details, "cached_tokens")
        if completion_details is not None:
            self._token_usage["reasoning_tokens"] += self._int_usage_field(
                completion_details, "reasoning_tokens"
            )

    @staticmethod
    def _usage_subfield(usage_obj: Any, key: str) -> Any:
        if isinstance(usage_obj, dict):
            return usage_obj.get(key)
        return getattr(usage_obj, key, None)

    @staticmethod
    def _int_usage_field(usage_obj: Any, key: str) -> int:
        value: Any
        if isinstance(usage_obj, dict):
            value = usage_obj.get(key, 0)
        else:
            value = getattr(usage_obj, key, 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

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
