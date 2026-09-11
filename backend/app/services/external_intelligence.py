from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass
from threading import Lock
from urllib.parse import quote
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class IntelligenceResult:
    indicator: str
    whois: str | None = None
    rdap: dict | None = None
    passive_dns: dict | None = None


class ExternalC2Intelligence:
    """Best-effort WHOIS/RDAP/passive-DNS enrichment with no hard dependency."""

    _cache: dict[tuple[str, str | None], tuple[float, IntelligenceResult]] = {}
    _cache_lock = Lock()

    def __init__(self, *, timeout: float = 5.0, passive_dns_url: str | None = None, cache_ttl_seconds: float | None = None) -> None:
        self.timeout = max(0.1, timeout)
        self.passive_dns_url = passive_dns_url or os.getenv("PASSIVE_DNS_URL")
        configured_ttl = os.getenv("PASSIVE_INTELLIGENCE_CACHE_TTL", "300")
        try:
            self.cache_ttl_seconds = max(0.0, cache_ttl_seconds if cache_ttl_seconds is not None else float(configured_ttl))
        except ValueError:
            self.cache_ttl_seconds = 300.0

    def lookup(self, indicator: str) -> IntelligenceResult:
        normalized = indicator.strip().lower()
        key = (normalized, self.passive_dns_url)
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(key)
            if cached and now - cached[0] < self.cache_ttl_seconds:
                return cached[1]
        result = IntelligenceResult(
            indicator=normalized,
            whois=self._whois(normalized),
            rdap=self._rdap(normalized),
            passive_dns=self._passive_dns(normalized),
        )
        with self._cache_lock:
            self._cache[key] = (now, result)
        return result

    @classmethod
    def clear_cache(cls) -> None:
        with cls._cache_lock:
            cls._cache.clear()

    def _whois(self, indicator: str) -> str | None:
        try:
            with socket.create_connection(("whois.iana.org", 43), timeout=self.timeout) as connection:
                connection.sendall(f"{indicator}\r\n".encode())
                chunks: list[bytes] = []
                while chunk := connection.recv(4096):
                    chunks.append(chunk)
        except OSError:
            return None
        return b"".join(chunks).decode("utf-8", errors="replace")[:20000] or None

    def _rdap(self, indicator: str) -> dict | None:
        url = f"https://rdap.org/ip/{quote(indicator)}" if _looks_like_ip(indicator) else f"https://rdap.org/domain/{quote(indicator)}"
        return self._json(url)

    def _passive_dns(self, indicator: str) -> dict | None:
        if not self.passive_dns_url:
            return None
        return self._json(self.passive_dns_url.format(indicator=quote(indicator)))

    def _json(self, url: str) -> dict | None:
        try:
            request = Request(url, headers={"Accept": "application/json", "User-Agent": "attack-trace-system/0.1"})
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return payload if isinstance(payload, dict) else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None


def _looks_like_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in value else socket.AF_INET, value)
        return True
    except OSError:
        return False
