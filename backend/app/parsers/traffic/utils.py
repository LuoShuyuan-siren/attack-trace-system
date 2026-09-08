"""网络流量分析共用工具函数。"""

import math
import re
from collections import Counter
from datetime import datetime, timezone

# 域名合法字符集
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def shannon_entropy(data: str | bytes) -> float:
    """计算 Shannon 熵。

    Args:
        data: 输入字符串或字节串。

    Returns:
        熵值（0 ~ 8.0 for bytes, 0 ~ log2(len(charset)) for str）。
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        counter = Counter(data)
        length = len(data)
    else:
        counter = Counter(data)
        length = len(data)

    entropy = 0.0
    for count in counter.values():
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_subdomain(domain: str) -> str:
    """提取域名的第一个子域标签。

    例如 "a1b2c3.example.com" -> "a1b2c3"
    "example.com" -> ""
    """
    if not domain:
        return ""
    parts = domain.strip(".").split(".")
    # 如果只有两段（example.com），没有子域
    if len(parts) <= 2:
        return ""
    return parts[0]


def is_valid_domain(domain: str) -> bool:
    """检查域名格式是否基本合法。"""
    if not domain or len(domain) > 253:
        return False
    parts = domain.strip(".").split(".")
    if len(parts) < 2:
        return False
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not _DOMAIN_LABEL_RE.match(part):
            return False
    return True


def parse_iso_timestamp(ts: str | float | int | None) -> datetime | None:
    """尝试将多种时间格式解析为 UTC datetime。

    支持的格式：
    - ISO 8601 字符串（含/不含时区）
    - Unix 时间戳（秒，float 或 int）
    """
    if ts is None:
        return None

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    if isinstance(ts, str):
        ts = ts.strip()
        if not ts:
            return None
        # 尝试 ISO 格式
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
        # 尝试纯数字时间戳
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, OSError):
            pass

    return None


def safe_int(value: object, default: int = 0) -> int:
    """安全转换为 int，失败返回默认值。"""
    try:
        return int(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return default


def safe_str(value: object, default: str = "") -> str:
    """安全转换为 str。"""
    if value is None:
        return default
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return default


def calculate_jitter_ratio(intervals: list[float]) -> float:
    """计算间隔序列的变异系数（CV = std/mean）。

    用于判断周期性/Beacon 行为，CV 越小越有规律。

    Returns:
        变异系数，如果均值 ≤ 0 或数据不足返回 1.0（无规律）。
    """
    if len(intervals) < 2:
        return 1.0
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return 1.0
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std = math.sqrt(variance)
    return std / mean


def detect_periodicity(
    timestamps: list[datetime],
    min_intervals: int = 3,
    max_jitter_ratio: float = 0.2,
) -> tuple[bool, float, float]:
    """检测时间序列是否具有周期性。

    统一的周期性 / Beacon 检测入口，被 HTTP / ICMP / Connection
    分析器共用。内部完成排序、间隔计算、jitter 判定。

    Args:
        timestamps: 事件时间戳列表（无需预排序）。
        min_intervals: 最少间隔数，不足则直接判定非周期。
        max_jitter_ratio: jitter (CV) 低于此值才视为周期性。

    Returns:
        (is_periodic, avg_interval, jitter_ratio)
        - is_periodic: 是否判定为周期性
        - avg_interval: 平均间隔秒数（非周期时为 0.0）
        - jitter_ratio: 间隔变异系数（数据不足时为 1.0）
    """
    if len(timestamps) < min_intervals + 1:
        return False, 0.0, 1.0

    sorted_ts = sorted(timestamps)
    intervals = [
        (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
        for i in range(len(sorted_ts) - 1)
    ]

    if len(intervals) < min_intervals:
        return False, 0.0, 1.0

    jitter = calculate_jitter_ratio(intervals)

    if jitter < max_jitter_ratio:
        avg_interval = sum(intervals) / len(intervals) if intervals else 0.0
        return True, avg_interval, jitter

    return False, 0.0, jitter


def rate_per_minute(
    timestamps: list[datetime],
    window_seconds: int = 60,
) -> float:
    """计算给定时间窗口内的最大速率（次/分钟）。

    使用滑动窗口，返回所有窗口中的最大值。
    """
    if len(timestamps) < 2:
        return 0.0

    sorted_ts = sorted(timestamps)
    from datetime import timedelta

    window = timedelta(seconds=window_seconds)
    max_rate = 0.0
    left = 0

    for right in range(len(sorted_ts)):
        while sorted_ts[right] - sorted_ts[left] > window:
            left += 1
        count = right - left + 1
        elapsed = (sorted_ts[right] - sorted_ts[left]).total_seconds()
        # 最小间隔保护：避免时间戳相同导致除零产生极大值
        if elapsed >= 1.0:
            rate = count / (elapsed / 60.0)
            max_rate = max(max_rate, rate)
        elif count >= 2:
            # 时间戳几乎相同但有多条记录，按最小1秒计算
            rate = count / (1.0 / 60.0)
            max_rate = max(max_rate, rate)

    return max_rate
