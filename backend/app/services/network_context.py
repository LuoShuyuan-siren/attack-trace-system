from __future__ import annotations

from collections import defaultdict
from hashlib import md5
from math import log
from typing import Any

from app.schemas.event import NormalizedEvent


class NetworkContextService:
    """重建网络会话并识别潜在隐蔽信道。"""

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = defaultdict(int)
        for ch in value:
            counts[ch] += 1
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * log(probability, 2)
        return entropy

    def reconstruct_sessions(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        grouped: dict[
            tuple[object, ...],
            list[NormalizedEvent],
        ] = defaultdict(list)

        for event in events:
            if event.source_type != "network_traffic" or event.network is None:
                continue
            key = self._flow_key(event)
            grouped[key].append(event)

        sessions: list[dict[str, Any]] = []
        for session_events in grouped.values():
            ordered = sorted(session_events, key=lambda item: item.timestamp)
            start = ordered[0].timestamp
            end = ordered[-1].timestamp
            first_network = ordered[0].network
            directions: dict[str, int] = defaultdict(int)
            flags: set[str] = set()
            tls_sni: set[str] = set()
            tls_certificates: set[str] = set()
            ja3_fingerprints: set[str] = set()
            byte_count = 0
            for event in ordered:
                network = event.network
                direction = (
                    f"{network.src_ip}:{network.src_port}->"
                    f"{network.dst_ip}:{network.dst_port}"
                )
                directions[direction] += 1
                byte_count += _event_bytes(event)
                event_flags = event.raw_data.get("tcp_flags") or event.raw_data.get("flags")
                if isinstance(event_flags, str):
                    flags.update(part.strip().upper() for part in event_flags.replace(",", " ").split())
                tls = _tls_data(event.raw_data)
                if tls:
                    for key in ("sni", "server_name"):
                        if tls.get(key):
                            tls_sni.add(str(tls[key]))
                    for key in ("fingerprint", "cert_fingerprint", "certificate_fingerprint"):
                        if tls.get(key):
                            tls_certificates.add(str(tls[key]))
                    ja3 = tls.get("ja3") or _calculate_ja3(tls)
                    if ja3:
                        ja3_fingerprints.add(ja3)
            sessions.append({
                "src_ip": first_network.src_ip,
                "src_port": first_network.src_port,
                "dst_ip": first_network.dst_ip,
                "dst_port": first_network.dst_port,
                "protocol": (first_network.protocol or "").upper() or None,
                "five_tuple": [
                    first_network.src_ip,
                    first_network.src_port,
                    first_network.dst_ip,
                    first_network.dst_port,
                    (first_network.protocol or "").upper() or None,
                ],
                "start_time": start,
                "end_time": end,
                "event_count": len(ordered),
                "duration_seconds": int((end - start).total_seconds()),
                "host": ordered[0].host.hostname,
                "direction_counts": dict(directions),
                "bytes": byte_count,
                "tcp_flags": sorted(flags),
                "state": _tcp_state(flags),
                "tls_sni": sorted(tls_sni),
                "tls_certificates": sorted(tls_certificates),
                "ja3": sorted(ja3_fingerprints),
                "reassembled_payloads": self._reassemble_payloads(ordered),
            })

        return sorted(sessions, key=lambda item: str(item["start_time"]))

    @staticmethod
    def _flow_key(event: NormalizedEvent) -> tuple[object, ...]:
        network = event.network
        protocol = (network.protocol or "").upper() or None
        left = (network.src_ip or "", network.src_port if network.src_port is not None else -1)
        right = (network.dst_ip or "", network.dst_port if network.dst_port is not None else -1)
        low, high = sorted((left, right))
        return (protocol, *low, *high)

    @staticmethod
    def _reassemble_payloads(events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        directions: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            network = event.network
            if not network or (network.protocol or "").upper() != "TCP":
                continue
            if event.raw_data.get("tcp_payload_hex") is None:
                continue
            direction = (
                f"{network.src_ip}:{network.src_port}->"
                f"{network.dst_ip}:{network.dst_port}"
            )
            directions[direction].append(event)

        payloads: list[dict[str, Any]] = []
        for direction, direction_events in directions.items():
            captured: list[tuple[int, bytes]] = []
            for event in direction_events:
                try:
                    sequence = int(event.raw_data.get("tcp_seq"))
                    data = bytes.fromhex(str(event.raw_data.get("tcp_payload_hex")))
                except (TypeError, ValueError):
                    continue
                if data:
                    captured.append((sequence, data))
            if not captured:
                continue

            retransmissions = 0
            out_of_order = 0
            highest_sequence = -1
            unique_segments: dict[int, bytes] = {}
            for sequence, data in captured:
                if sequence < highest_sequence:
                    out_of_order += 1
                if sequence in unique_segments and unique_segments[sequence] == data:
                    retransmissions += 1
                else:
                    unique_segments.setdefault(sequence, data)
                highest_sequence = max(highest_sequence, sequence)

            segments = list(unique_segments.items())
            if not segments:
                continue

            segments.sort(key=lambda item: item[0])
            assembled = bytearray()
            next_sequence: int | None = None
            gaps = 0
            for sequence, data in segments:
                if next_sequence is None:
                    next_sequence = sequence
                if sequence > next_sequence:
                    gaps += sequence - next_sequence
                    next_sequence = sequence
                overlap = max(0, next_sequence - sequence)
                chunk = data[overlap:]
                remaining = 65536 - len(assembled)
                if remaining <= 0:
                    break
                assembled.extend(chunk[:remaining])
                next_sequence += len(chunk)

            preview = bytes(assembled[:4096]).decode("utf-8", errors="replace")
            payloads.append({
                "direction": direction,
                "bytes": len(assembled),
                "gaps": gaps,
                "out_of_order_segments": out_of_order,
                "retransmissions": retransmissions,
                "preview": preview,
                "application_protocol": _application_protocol(bytes(assembled)),
            })
        return payloads

    def summarize_covert_channels(self, events: list[NormalizedEvent]) -> dict[str, Any]:
        suspicious: list[dict[str, Any]] = []
        evidence_by_ip: dict[str, list[str]] = defaultdict(list)

        for event in events:
            if event.source_type != "network_traffic" or event.network is None:
                continue

            query = None
            if event.event_type == "dns_query":
                dns = event.raw_data.get("dns") if isinstance(event.raw_data, dict) else None
                query = dns.get("query") if isinstance(dns, dict) else None
                query = query or (dns.get("query_name") if isinstance(dns, dict) else None)
            elif event.event_type in {"http_request", "http_traffic"}:
                http = event.raw_data.get("http") if isinstance(event.raw_data, dict) else None
                if isinstance(http, dict):
                    query = http.get("url")

            if not query:
                continue

            query_str = str(query)
            if len(query_str) < 20:
                continue

            label = query_str.split(".")[0]
            entropy = self._shannon_entropy(label)
            is_suspicious = (
                len(query_str) > 40 or entropy > 3.3 or query_str.count(".") >= 4
            )
            if not is_suspicious:
                continue

            detail = {
                "src_ip": event.network.src_ip,
                "dst_ip": event.network.dst_ip,
                "query": query_str,
                "entropy": round(entropy, 3),
                "domain_length": len(query_str),
                "event_id": event.event_id,
                "timestamp": event.timestamp,
            }
            suspicious.append(detail)
            evidence_by_ip[str(event.network.src_ip)].append(query_str)

        return {
            "count": len(suspicious),
            "suspicious_domains": suspicious,
            "by_src_ip": {
                key: sorted(set(values)) for key, values in evidence_by_ip.items()
            },
        }


def _event_bytes(event: NormalizedEvent) -> int:
    for key in ("packet_length", "bytes", "bytes_total", "bytes_out", "payload_length"):
        try:
            value = event.raw_data.get(key)
            if value is not None:
                return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def _tcp_state(flags: set[str]) -> str:
    if "RST" in flags:
        return "reset"
    if "FIN" in flags:
        return "closed"
    if "SYN" in flags and "ACK" not in flags:
        return "syn_sent"
    if "SYN" in flags and "ACK" in flags:
        return "syn_ack"
    return "established" if flags else "unknown"


def _tls_data(raw_data: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("tls", "ssl"):
        value = raw_data.get(key)
        if isinstance(value, dict):
            return value
    return None


def _calculate_ja3(tls: dict[str, Any]) -> str | None:
    fields = (
        tls.get("version"),
        tls.get("ciphers") or tls.get("cipher_suites"),
        tls.get("extensions"),
        tls.get("elliptic_curves") or tls.get("supported_groups"),
        tls.get("ec_point_formats") or tls.get("point_formats"),
    )
    if not all(value not in (None, "", "-") for value in fields):
        return None
    ja3_string = ",".join(_ja3_part(value) for value in fields)
    return md5(ja3_string.encode("utf-8"), usedforsecurity=False).hexdigest()


def _ja3_part(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return "-".join(str(item) for item in value)
    return str(value).replace(" ", "")


def _application_protocol(payload: bytes) -> str | None:
    normalized = payload.lstrip().upper()
    if normalized.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"PATCH ")):
        return "HTTP_REQUEST"
    if normalized.startswith(b"HTTP/"):
        return "HTTP_RESPONSE"
    if payload.startswith(b"\x16\x03"):
        return "TLS"
    return None
