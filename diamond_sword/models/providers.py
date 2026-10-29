"""Free model providers (names/limits only) + local Ollama. Config, not credentials. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
__all__ = ["Provider", "FREE_PROVIDERS", "OLLAMA"]


@dataclass(frozen=True)
class Provider:
    name: str
    model: str
    rpm: int   # requests/min budget hint for rotation


FREE_PROVIDERS = (
    Provider("groq", "llama-3.3-70b", 30),
    Provider("gemini", "gemini-2.0-flash", 15),
    Provider("cerebras", "llama-3.3-70b", 30),
    Provider("openrouter", "free", 20),
)
OLLAMA = Provider("ollama", "qwen2.5-coder", 10_000)   # local, effectively unlimited
