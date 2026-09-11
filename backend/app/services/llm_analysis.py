import json

from app.services.llm_client import LLMClient
from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
)


def analyze_current_attack() -> str:
    """让大模型综合当前事件、检测结果和 ATT&CK 映射。"""

    context = {
        "events": [
            event.model_dump(mode="json")
            for event in EVENTS[-30:]
        ],
        "detections": [
            detection.model_dump(mode="json")
            for detection in DETECTIONS[-30:]
        ],
        "attack_mappings": [
            mapping.to_dict()
            for mapping in ATTACK_MAPPINGS[-30:]
        ],
    }

    prompt = f"""
以下是网络安全溯源系统得到的分析结果：

{json.dumps(context, ensure_ascii=False, indent=2)}

请完成以下分析：

1. 判断当前是否存在明显攻击行为
2. 概括攻击者可能采用的攻击步骤
3. 结合 MITRE ATT&CK 技术解释攻击链
4. 指出关键证据
5. 给出最终溯源分析结论

不要编造输入数据中不存在的事实。
"""

    client = LLMClient()

    return client.chat(
        prompt,
        system_prompt=(
            "你是一名网络安全事件响应与攻击溯源专家。"
            "请基于给定证据进行分析，区分事实和推断。"
        ),
    )