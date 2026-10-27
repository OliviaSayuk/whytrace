from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx
from dotenv import load_dotenv

load_dotenv()


@dataclass
class LLMConfig:
    name: str
    base_url: str
    api_key: str
    model: str
    extra_headers: dict[str, str]


def resolve_llm() -> LLMConfig | None:
    meterless = os.getenv("METERLESS_TOKEN", "").strip()
    if meterless:
        base = os.getenv("METERLESS_BASE_URL", "http://127.0.0.1:8088/v1").rstrip("/")
        if base.endswith("/chat/completions"):
            base = base[: -len("/chat/completions")]
        if not base.endswith("/v1"):
            base = base + "/v1"
        return LLMConfig(
            name="meterless",
            base_url=base,
            api_key=meterless,
            model=os.getenv("METERLESS_MODEL", "meterless/auto"),
            extra_headers={"meterless-app": "whytrace", "meterless-scope": "user"},
        )
    nvidia = os.getenv("NVIDIA_API_KEY", "").strip()
    if nvidia:
        return LLMConfig(
            name="nvidia-nemotron",
            base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/"),
            api_key=nvidia,
            model=os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3-nano-30b-a3b"),
            extra_headers={},
        )
    openai = os.getenv("OPENAI_API_KEY", "").strip()
    if openai:
        return LLMConfig(
            name="openai",
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            api_key=openai,
            model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            extra_headers={},
        )
    return None


def complete_json(system: str, user: str, timeout: float = 180.0) -> tuple[dict, str]:
    cfg = resolve_llm()
    if cfg is None:
        raise RuntimeError("no_llm")
    payload = {
        "model": cfg.model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    headers = {
        "Authorization": f"Bearer {cfg.api_key}",
        "Content-Type": "application/json",
        **cfg.extra_headers,
    }
    url = cfg.base_url + "/chat/completions"
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
    text = data["choices"][0]["message"]["content"]
    parsed = _extract_json(text)
    return parsed, f"{cfg.name}:{cfg.model}"


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text[: -3]
        text = text.strip()
        if text.startswith("json"):
            text = text[4:].strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("model did not return JSON")
    return json.loads(text[start : end + 1])
