from fastapi import APIRouter, Query

from app.services.external_intelligence import ExternalC2Intelligence

router = APIRouter()


@router.get("/lookup")
def lookup_indicator(
    indicator: str = Query(..., min_length=1, max_length=253),
) -> dict[str, object]:
    """查询 WHOIS、RDAP 及已配置的 Passive DNS 数据源。"""
    result = ExternalC2Intelligence().lookup(indicator)
    return {
        "indicator": result.indicator,
        "whois": result.whois,
        "rdap": result.rdap,
        "passive_dns": result.passive_dns,
    }