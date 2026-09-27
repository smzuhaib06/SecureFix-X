"""
Phase 5G — AI Provider Abstraction

Abstracts all AI provider calls behind a common interface.

Design principles:
- All providers implement the same BaseAIProvider protocol
- The provider is selected at runtime via SECUREFIX_AI_PROVIDER env var
- If no provider is configured, the system falls back to DeterministicProvider
  (which produces structured output from the evidence package alone, with no
  AI inference)
- Provider credentials are NEVER stored in this module
- The AI reasoning result must include a grounding confidence (0.0–1.0)
  alongside the textual output

Providers:
  auto         — detect best available provider (default)
  google       — Google Generative AI (Gemini) via google-generativeai
  openai       — OpenAI API via openai package
  deterministic — no LLM call, evidence summary only

Environment variables:
  SECUREFIX_AI_PROVIDER    = auto | google | openai | deterministic
  GOOGLE_API_KEY           = Google Generative AI API key
  OPENAI_API_KEY           = OpenAI API key
  SECUREFIX_AI_MODEL       = override model name (optional)
"""
from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


# ── Provider response ──────────────────────────────────────────────────────────

class AIProviderResponse:
    """Response from any AI provider."""
    def __init__(
        self,
        text: str,
        provider: str,
        model: str,
        tokens_used: int = 0,
        latency_ms: int = 0,
        error: Optional[str] = None,
    ):
        self.text = text
        self.provider = provider
        self.model = model
        self.tokens_used = tokens_used
        self.latency_ms = latency_ms
        self.error = error

    @property
    def succeeded(self) -> bool:
        return self.error is None and bool(self.text)


# ── Base provider ──────────────────────────────────────────────────────────────

class BaseAIProvider(ABC):
    """Abstract base for all AI providers."""
    name: str = "base"

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
    ) -> AIProviderResponse:
        """Generate a response from the AI model."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider is properly configured."""


# ── Google Generative AI Provider ─────────────────────────────────────────────

class GoogleAIProvider(BaseAIProvider):
    """Google Generative AI (Gemini) provider."""
    name = "google"
    _DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(self):
        self._api_key = os.environ.get("GOOGLE_API_KEY", "")
        self._model_name = os.environ.get("SECUREFIX_AI_MODEL", self._DEFAULT_MODEL)

    def is_available(self) -> bool:
        if not self._api_key:
            return False
        try:
            import google.generativeai  # noqa: F401
            return True
        except ImportError:
            return False

    def generate(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
    ) -> AIProviderResponse:
        t0 = time.time()
        try:
            import google.generativeai as genai
            genai.configure(api_key=self._api_key)
            model_kwargs: Dict[str, Any] = {}
            if system_instruction:
                model_kwargs["system_instruction"] = system_instruction
            model = genai.GenerativeModel(self._model_name, **model_kwargs)
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": temperature,
                    "max_output_tokens": max_output_tokens,
                },
            )
            text = response.text or ""
            tokens = 0
            try:
                tokens = response.usage_metadata.total_token_count or 0
            except Exception:
                pass
            latency = int((time.time() - t0) * 1000)
            return AIProviderResponse(
                text=text,
                provider=self.name,
                model=self._model_name,
                tokens_used=tokens,
                latency_ms=latency,
            )
        except Exception as exc:
            latency = int((time.time() - t0) * 1000)
            return AIProviderResponse(
                text="",
                provider=self.name,
                model=self._model_name,
                latency_ms=latency,
                error=str(exc),
            )


# ── OpenAI Provider ────────────────────────────────────────────────────────────

class OpenAIProvider(BaseAIProvider):
    """OpenAI API provider."""
    name = "openai"
    _DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self):
        self._api_key = os.environ.get("OPENAI_API_KEY", "")
        self._model_name = os.environ.get("SECUREFIX_AI_MODEL", self._DEFAULT_MODEL)

    def is_available(self) -> bool:
        if not self._api_key:
            return False
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False

    def generate(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
    ) -> AIProviderResponse:
        t0 = time.time()
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self._api_key)
            messages = []
            if system_instruction:
                messages.append({"role": "system", "content": system_instruction})
            messages.append({"role": "user", "content": prompt})
            response = client.chat.completions.create(
                model=self._model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_output_tokens,
            )
            text = response.choices[0].message.content or ""
            tokens = response.usage.total_tokens if response.usage else 0
            latency = int((time.time() - t0) * 1000)
            return AIProviderResponse(
                text=text,
                provider=self.name,
                model=self._model_name,
                tokens_used=tokens,
                latency_ms=latency,
            )
        except Exception as exc:
            latency = int((time.time() - t0) * 1000)
            return AIProviderResponse(
                text="",
                provider=self.name,
                model=self._model_name,
                latency_ms=latency,
                error=str(exc),
            )


# ── Deterministic fallback provider ───────────────────────────────────────────

class DeterministicProvider(BaseAIProvider):
    """
    Deterministic fallback: no LLM call.
    Produces a structured evidence summary from the evidence package.
    Used when no AI provider is configured, or when AI is disabled.
    Grounding is inherently maximal (no inference possible).
    """
    name = "deterministic"

    def is_available(self) -> bool:
        return True

    def generate(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
    ) -> AIProviderResponse:
        # Extract key evidence lines from the prompt (naive but reliable)
        lines = prompt.splitlines()
        evidence_lines = [
            l.strip() for l in lines
            if any(marker in l for marker in ["Finding:", "Evidence:", "File:", "Line:", "CWE:", "CVE:"])
        ][:20]
        summary = (
            "DETERMINISTIC PROVIDER: No AI model is configured.\n"
            "Evidence collected by SECUREFIX agents:\n"
            + "\n".join(f"  - {l}" for l in evidence_lines)
            + (
                "\nNo AI-generated reasoning was produced. "
                "Configure SECUREFIX_AI_PROVIDER=google or SECUREFIX_AI_PROVIDER=openai "
                "with appropriate API credentials to enable AI reasoning."
            )
        )
        return AIProviderResponse(
            text=summary,
            provider=self.name,
            model="deterministic-v1",
            tokens_used=0,
            latency_ms=0,
        )


# ── Provider factory ───────────────────────────────────────────────────────────

def get_provider() -> BaseAIProvider:
    """
    Return the best available AI provider based on environment configuration.

    Selection order for 'auto':
      1. Google Generative AI (if GOOGLE_API_KEY set and package available)
      2. OpenAI (if OPENAI_API_KEY set and package available)
      3. DeterministicProvider (always available — never fails)
    """
    pref = os.environ.get("SECUREFIX_AI_PROVIDER", "auto").lower()

    if pref == "google":
        p = GoogleAIProvider()
        if p.is_available():
            return p
        return DeterministicProvider()

    if pref == "openai":
        p = OpenAIProvider()
        if p.is_available():
            return p
        return DeterministicProvider()

    if pref == "deterministic":
        return DeterministicProvider()

    # auto
    google = GoogleAIProvider()
    if google.is_available():
        return google

    openai_p = OpenAIProvider()
    if openai_p.is_available():
        return openai_p

    return DeterministicProvider()
