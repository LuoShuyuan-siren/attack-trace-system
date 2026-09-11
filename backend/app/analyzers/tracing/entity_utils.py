"""攻击图实体 ID 与节点构造工具。"""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import PurePath

from app.schemas.attack_graph import AttackNode


SUPPORTED_NODE_TYPES = {
    "host",
    "user",
    "process",
    "file",
    "ip",
    "domain",
    "registry",
    "service",
}


def host_id(hostname: str) -> str:
    return f"host:{_component(hostname, 'hostname')}"


def user_id(hostname: str, username: str) -> str:
    return f"user:{_component(hostname, 'hostname')}:{_component(username, 'username')}"


def process_id(hostname: str, pid: int) -> str:
    if pid < 0:
        raise ValueError("pid must not be negative")
    return f"process:{_component(hostname, 'hostname')}:{pid}"


def ip_id(value: str) -> str:
    normalized = value.strip()
    try:
        ip_address(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc
    return f"ip:{normalized}"


def object_id(hostname: str, object_type: str, value: str) -> str:
    hostname = _component(hostname, "hostname")
    value = value.strip()
    if not value:
        raise ValueError(f"{object_type} must be non-empty")
    if object_type == "file":
        return f"file:{hostname}:{value}"
    if object_type == "registry":
        return f"registry:{hostname}:{value}"
    if object_type == "service":
        return f"service:{hostname}:{value}"
    raise ValueError(f"unsupported host-scoped entity type: {object_type}")


def node_from_id(node_id: str) -> AttackNode | None:
    """由规范化实体 ID 构造占位节点。"""

    node_type, separator, value = node_id.strip().partition(":")
    if not separator or not value or node_type not in SUPPORTED_NODE_TYPES:
        return None

    if node_type == "host" and not _single_value(value):
        return None
    if node_type == "ip":
        try:
            ip_address(value)
        except ValueError:
            return None
    if node_type == "domain" and not _single_value(value):
        return None
    if node_type in {"user", "process", "file", "registry", "service"}:
        hostname, nested_separator, nested_value = value.partition(":")
        if not nested_separator or not _single_value(hostname) or not nested_value.strip():
            return None
        if node_type == "process" and not nested_value.isdigit():
            return None

    name = value
    if node_type in {"user", "process", "file", "registry", "service"}:
        parts = value.split(":", 1)
        if len(parts) == 2:
            name = parts[1]
    if node_type == "file":
        name = PurePath(name).name or name

    normalized_id = f"{node_type}:{value}"
    return AttackNode(node_id=normalized_id, node_type=node_type, name=name)


def _component(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized or ":" in normalized:
        raise ValueError(f"{label} must be non-empty and must not contain ':'")
    return normalized


def _single_value(value: str) -> bool:
    return bool(value.strip()) and ":" not in value
