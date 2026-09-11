# ADFA-LD 评估说明

ADFA-LD 原始文件是空格分隔的 Linux 系统调用编号序列，不是 auditd 日志，不能直接按主机日志上传。项目提供课程级序列基线评估入口：使用 `Training_Data_Master` 建立正常行为基线，再对 `Attack_Data_Master` 中的每个样本独立评分。

在项目根目录执行：

```powershell
$env:PYTHONPATH = "backend"
python scripts/evaluate_adfa_ld.py --dataset ADFA-LD --output backend/examples/adfa_ld_evaluation.json
```

评估结果包含正常样本数、攻击样本数、异常阈值、检出率、按攻击类别统计、ATT&CK 技术和攻击图规模。也可以使用 `--max-normal` 和 `--max-attack` 先运行小规模冒烟测试。

当前实现将 ADFA-LD 类别对应的 ATT&CK 编号作为“数据集上下文标注”，只对已经通过序列异常检测的样本附加该标注，不把目录名称当作检测证据。不同攻击类别和不同样本不会被拼接成一条真实攻击链。

最近一次本地全量结果：833 个正常样本建立基线，746 个攻击样本检出 171 个，检出率 22.92%，正常样本误报 9 个、误报率 1.08%，生成 171 条 ATT&CK 映射和 171 条攻击图关系。