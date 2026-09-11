import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_PATH)

class LLMClient:
    """通用 OpenAI-compatible 大模型客户端。"""

    def __init__(self) -> None:
        self.api_key = os.getenv("LLM_API_KEY")
        self.base_url = os.getenv(
            "LLM_BASE_URL",
            "https://api.openai.com/v1",
        ).rstrip("/")
        self.model = os.getenv("LLM_MODEL")

    def is_configured(self) -> bool:
        """检查大模型 API 是否已配置。"""
        return bool(self.api_key and self.model)

    def chat(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
    ) -> str:
        if not self.is_configured():
            raise RuntimeError(
                "LLM API 未配置，请设置 LLM_API_KEY 和 LLM_MODEL"
            )

        messages = []

        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt,
            })

        messages.append({
            "role": "user",
            "content": prompt,
        })

        payload = {
            "model": self.model,
            "messages": messages,
        }

        request = Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=60) as response:
                result = json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as exc:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )
            raise RuntimeError(
                f"LLM API HTTP {exc.code}: {detail}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"无法连接 LLM API: {exc.reason}"
            ) from exc

        try:
            return result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                f"LLM API 返回格式异常: {result}"
            ) from exc