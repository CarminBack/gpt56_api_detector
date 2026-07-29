# GPT-5.6 API 检测器

这个工具用一个你信任的 GPT-5.6 API，检测另一个待测 API 是否具备 GPT-5.6 的真实能力。提供两种傻瓜式入口：单次严格检测和随机间隔持续监控。

## Windows 一键启动

解压整个 ZIP 后，根据用途双击：

- `start_detector.bat`：运行一次严格检测，完成后生成报告。
- `start_monitor.bat`：持续随机检测，按 `Ctrl+C` 停止。

两种入口都会逐项询问 API 地址、模型名和 key，不需要手写命令。需要 Python 3.10 或更高版本，不需要安装第三方 Python 库。

## 单次严格检测

双击 `start_detector.bat`，按提示输入：

1. 可信 GPT-5.6 API 地址、模型名和 key；
2. 待测 API 地址、模型名和 key；
3. 报告文件名，直接回车使用默认值。

固定判定标准：20 个进入待测端判定分母的随机挑战；完整状态至少命中 15 次；删除 item ID 后至少命中 15 次；message-only、损坏密文和明文泄漏均必须为 0。

## 随机间隔持续监控

双击 `start_monitor.bat`，输入两个 API 后，间隔设置直接按回车即可。默认每轮完成后随机等待 20–40 秒。窗口保持开启，需要停止时按一次 `Ctrl+C`。

持续模式会滚动统计最近 20 个到达待测 API 的候选尝试，包括最终仍发生传输错误的轮次。完整状态和删除 ID 状态都至少命中 15 次、阴性对照为 0，并且窗口内没有候选错误或重试，才会通过。最初不足 20 个候选尝试时显示 `warming_up`。详细说明见 [MONITORING_CN.md](MONITORING_CN.md)。

持续模式自动采用：

- 每轮新的密码学随机挑战；
- 三种计算任务均衡轮换；
- 使用经可信端实测稳定的规范种子与召回提示；
- 随机改变四类候选请求的发送顺序；
- 在用户设置的范围内随机等待。

这些措施只能降低简单的固定周期和固定提示词识别，不能做到不可识别。中转仍可能识别 Responses reasoning replay，并只把探针流量转发给 GPT-5.6。

## Linux / macOS

```bash
sh start_detector.sh   # 单次严格检测
sh start_monitor.sh    # 持续随机监控
```

## 需要准备什么

- 一个你确定是真的 GPT-5.6 的可信 API；
- 一个想检查的待测 API；
- 两边都支持 `/v1/responses`；
- 对应的 API 地址、模型名和 key。

可信模型直接回车默认使用 `gpt-5.6-sol`。两个 API 使用同一个 key 时，可以在向导中选择复用。

API key 输入时不会显示，不会作为命令行参数传递，也不会写入报告。key 只临时存在于检测子进程中，程序结束后不会新增用户或系统环境变量。

程序会发送标准 API 请求头。待测接口返回 429、500、502、503、504 或发生连接中断时，会用随机退避有限重试；四类候选请求之间也会随机等待 2–5 秒。403 不会盲目重试。即使重试后成功，该轮仍留在 20 次分母中并阻止“通过”，避免只保留成功路由造成假阳性。

## 它是怎么检测的

程序生成一个新的随机十位数字，并在本地算出正确答案。可信 GPT-5.6 在不可见的内部计算中处理数字，表面只回答 `READY`。程序随后把可信 API 返回的加密数据交给待测 API，但不告诉它原数字和正确答案。

如果待测 API 真能处理 GPT-5.6 的数据，它就能恢复答案。程序还会删除 item ID、只发送普通文字，以及故意损坏密文。只有正常状态反复答对，而所有反向检查均没有异常命中，才会通过。

## 怎样看结果

- `gpt_5_6_encrypted_state_compatible`：通过，待测 API 高度符合 GPT-5.6 的能力。
- `warming_up`：持续监控尚未累积 20 个候选尝试。
- `not_compatible_in_this_probe` 或 `not_compatible_in_this_window`：本次或最近窗口未观察到兼容能力。
- `inconclusive`：部分证据未达到严格门槛。`inconclusive_candidate_unstable` 表示窗口内发生过候选错误或重试，稳定性不足，禁止判定通过。
- `suspicious`：阴性对照异常命中，结果不可信。
- `invalid`：检测请求普通文字泄漏了正确答案。

网络错误不会直接产生“不兼容”结论，但会保留在判定分母中，并阻止该窗口给出“兼容”结论。这样既不会把网络故障误判成模型能力不足，也不能靠丢弃失败轮次凑出通过。

通过不能区分 GPT-5.6 Sol、Terra 和 Luna，也无法区分本地运行 GPT-5.6 与透明转发给 GPT-5.6。

## 原命令行版本

`gpt56_reasoning_probe.py` 和 `gpt56_reasoning_monitor.py` 都可以直接用于自动化。查看参数：

```powershell
python .\gpt56_reasoning_probe.py --help
python .\gpt56_reasoning_monitor.py --help
```

示例：

```powershell
$env:TRUSTED_API_KEY = '可信API密钥'
$env:CANDIDATE_API_KEY = '待测API密钥'

python .\gpt56_reasoning_monitor.py `
  --trusted-base-url https://trusted.example/v1 `
  --trusted-model gpt-5.6-sol `
  --candidate-base-url https://candidate.example/v1 `
  --candidate-model model-to-test `
  --min-interval 20 `
  --max-interval 40 `
  --window 20 `
  --required-matches 15 `
  --output monitor-report.json

Remove-Item Env:TRUSTED_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:CANDIDATE_API_KEY -ErrorAction SilentlyContinue
```

更完整的统计方法、证据边界和安全分析见 [TECHNICAL_REPORT_CN.md](TECHNICAL_REPORT_CN.md)。



