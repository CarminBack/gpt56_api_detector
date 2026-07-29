[README.md](https://github.com/user-attachments/files/30490582/README.md)
# GPT-5.6 API 检测器

这个工具用一个你信任的 GPT-5.6 API，检测另一个待测 API 背后的模型是否是 GPT-5.6。

Windows 用户解压后双击启动，按提示输入两个 API 的地址、模型名和 key，程序就会自动完成严格检测并生成报告。不需要安装 Python 库，也不需要手写命令。

## 一键启动

### Windows

1. 解压整个 ZIP，不能只打开压缩包内的单个文件。
2. 双击 `start_detector.bat`。
3. 按提示输入可信 API 和待测 API。
4. 等待检测完成。窗口最后会显示 JSON 报告的位置。

需要 Python 3.10 或更高版本。如果提示找不到 Python，请安装 Python 并勾选“Add Python to PATH”。

### Linux / macOS

在解压目录运行：

```bash
sh start_detector.sh
```

也可以直接运行：

```bash
python3 gpt56_detector_wizard.py
```

## 需要输入什么

可信 API：

- API 地址，例如 `https://trusted.example/v1`；
- 模型名，直接回车默认使用 `gpt-5.6-sol`；
- API key。

待测 API：

- API 地址，例如 `https://candidate.example/v1`；
- 服务商要求的实际模型名；
- API key。若与可信 API 相同，可以直接选择复用。

最后可以直接回车使用自动生成的报告文件名。

API key 输入时不会显示，不会作为命令行参数传递，也不会写入报告。启动器只把 key 临时交给检测子进程；程序结束后密钥随子进程消失，不会新增用户或系统环境变量。

## 判定标准

一键启动器固定使用严格标准，不提供降低门槛的选项：

- 收集 20 个有效随机挑战；
- 完整数据测试至少答对 15 次；
- 删除数据编号后至少答对 15 次；
- 只发送普通文字时必须 0 次命中；
- 故意破坏加密数据后必须 0 次命中；
- 发给待测 API 的普通文字中不能出现正确答案。

也就是说，一键启动降低的是操作门槛，不是检测通过门槛。临时网络错误、路由变化和限流仍可能造成不通过或结果不确定，重要结果可以换一个时间再完整运行一次。

## 它能告诉你什么

如果待测 API 通过，说明它能够正确读取 GPT-5.6 才能正常接续的加密信息，这是判断待测 API 是否提供 GPT-5.6 的强证据。

但有两个无法绕过的边界：

1. 无法区分 GPT-5.6 Sol、Terra 和 Luna，因为这三个模型可以读取彼此产生的加密信息。
2. 如果待测 API 暗中把请求转发给真正的 GPT-5.6，它也会通过。普通 API 检测无法区分本地运行和转发调用。

因此，通过代表待测 API 高度符合 GPT-5.6 的真实能力，不是服务器硬件或模型权重的身份证明。

## 检测原理

每次测试，程序都会生成一个新的随机十位数字，并在本地算出正确答案。

可信 GPT-5.6 会在不可见的内部计算中处理这个数字，表面只回答 `READY`。然后程序把可信 API 返回的加密数据交给待测 API，但不会告诉它原数字和正确答案。

如果待测 API 真能处理 GPT-5.6 的数据，它就能说出正确答案。程序还会：

- 删除数据编号后再测，排除按编号查询旧答案；
- 只发送表面的 `READY`，确认答案没有藏在普通文字里；
- 故意破坏加密数据，确认答案确实来自原始加密内容。

只有正常测试反复答对，并且所有反向检查都没有异常命中，才会通过。

## 怎样看结果

- `gpt_5_6_encrypted_state_compatible`：通过，待测 API 高度符合 GPT-5.6 的行为特征。
- `not_compatible_in_this_probe`：本次未观察到 GPT-5.6 能力。
- `inconclusive`：结果不稳定或有效测试不足，建议重试。
- `suspicious`：反向检查异常命中，可能有答案泄漏、缓存串扰或接口问题。
- `invalid`：正确答案进入了发给待测 API 的普通文字，本次测试作废。

一次未通过不一定代表对方永远不是 GPT-5.6，也可能是临时路由、限流、接口不兼容或模型配置错误。

## 保留的原命令行版本

原始检测脚本 `gpt56_reasoning_probe.py` 完整保留，适合自动化、CI 或自定义参数：

```powershell
$env:TRUSTED_API_KEY = '可信API的密钥'
$env:CANDIDATE_API_KEY = '待测API的密钥'

python .\gpt56_reasoning_probe.py `
  --trusted-base-url https://trusted.example/v1 `
  --trusted-model gpt-5.6-sol `
  --candidate-base-url https://candidate.example/v1 `
  --candidate-model model-to-test `
  --trials 20 `
  --min-match-rate 0.75 `
  --min-matches 15 `
  --output probe-report.json

Remove-Item Env:TRUSTED_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:CANDIDATE_API_KEY -ErrorAction SilentlyContinue
```

查看全部参数：

```powershell
python .\gpt56_reasoning_probe.py --help
```

## 报告和隐私

生成的 JSON 会保存检测次数、命中情况、响应时间、HTTP 状态和用于核对的哈希值。它不会保存 API key、随机十位数字、正确答案、待测 API 原始回答或原始加密数据。

更完整的统计方法、证据边界和安全分析见 [TECHNICAL_REPORT_CN.md](TECHNICAL_REPORT_CN.md)。

