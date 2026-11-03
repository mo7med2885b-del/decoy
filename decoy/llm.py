"""Vultr Serverless Inference client (OpenAI-compatible). The key stays on the control plane only."""
import json
import re

import httpx

from .config import env
from .guard import Budget


def available() -> bool:
    return bool(env("VULTR_INFERENCE_KEY"))


def model_name() -> str:
    return env("DECOY_MODEL", "glm-5.3-flash") if available() else "rule-based (no key)"


def chat(budget: Budget, system: str, user: str, image_b64: str | None = None, max_tokens: int = 1500,
         model: str | None = None) -> str:
    budget.check()
    content: list | str = user
    if image_b64:
        content = [{"type": "text", "text": user},
                   {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + image_b64}}]
    body = {"model": model or env("DECOY_MODEL", "glm-5.3-flash"), "max_tokens": max_tokens, "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}]}
    timeout = max(5.0, min(60.0, budget.time_left()))
    r = httpx.post(env("VULTR_INFERENCE_URL", "https://api.vultrinference.com/v1").rstrip("/") + "/chat/completions",
                   headers={"Authorization": "Bearer " + env("VULTR_INFERENCE_KEY")}, json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    usage = data.get("usage") or {}
    budget.record(int(usage.get("prompt_tokens", 2000)), int(usage.get("completion_tokens", max_tokens)))
    return (data["choices"][0]["message"].get("content") or "").strip()


def parse_json(text: str) -> dict | None:
    """Pull the first JSON object out of a model answer."""
    text = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(), flags=re.M)
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    break
        start = text.find("{", start + 1)
    return None
