# GPT-5.6 混用检测器 v4.1.1 技术报告

## 1. 目标与非目标

v4.1.1 的正式目标是识别 GPT-5.6 内部 Sol、Terra、Luna 的混用或路由不一致。检测器只请求待测端，不再依赖可信端在线生成挑战。

系统保留三类证据：

1. Juice 预算指纹及其确定性反改写控制；
2. 三个固定行为探针的类别分布指纹；
3. 普通/Native与无历史/固定32K上下文之间的请求路径对照。

系统不证明模型权重文件名称、服务器物理归属或普通业务请求一定使用相同路由。指纹匹配度不是路由比例，也不是贝叶斯后验身份概率。

## 2. 证据分层

### 2.1 Juice

Juice 提示从版本化模板池选择，使用恒等变形保证最终请求的仍是原预算值。分类先检查申报型号，再检查其他型号，避免共享值被误报。

每个思考档独立要求足够的申报型号命中。网络错误、拒答和未知数字不算其他型号，只降低数据质量。明确排斥申报型号的已知指纹触发确定性 mismatch，并以带类型、时间、探针和原证据的 sticky event 保留。

### 2.2 32/48输出完整性

该探针要求精确返回32或48。只有返回纯数字40，或长度大于2且以40开头的纯数字，才触发输出改写硬异常。其他非目标输出是无效证据，不直接推断中转篡改。

### 2.3 显式覆盖

检测器生成不属于已知Juice指纹且不以8、16、40开头的显式数字 N。developer/user共同定义N，再检查输出是否仍被隐藏规则改回已知预算值。此层只覆盖简单语义覆盖攻击。

### 2.4 固定行为指纹

正式内置探针为：固定随机国家、固定随机鸟、b80字符计数。题面、developer、effort、normalizer、请求格式和上下文均由哈希契约冻结。

固定题面是指纹的一部分。更换用户题面不是“鲁棒性改写”，而是另一个探针。系统提示轻微变化也可能影响分布，所以只有精确官方契约可产生正式强指向。

## 3. 基础指纹与运行策略分离

基础指纹文件 `trusted_fingerprint_v3.json` 保存：

- 三模型可信类别计数；
- Laplace/Dirichlet平滑后的模型分布；
- 模型间 Jensen–Shannon 差异 S；
- 同模型跨时间窗口漂移 D；
- 权重 `w = 0`（S≤D或S≤0），否则 `min(1,(S-D)/S)`。

v4.1.1 实施前后文件SHA-256均为：

```text
B637FCF4D959389B14779A32C6B40DD8346501D84AD7B873C928A8783E421FE5
```

请求数变化只改变待测抽样误差，不改变可信答案分布，因此不重建基础指纹。

新增 `fingerprint_runtime_policy_v4_1_1.json` 保存六个官方运行契约、config hash、runtime signature、计划格、顶层唯一三档阈值和研究摘要。契约只保存 `decision_level`，评分前由加载器从顶层阈值表注入；JSON中不复制契约阈值。策略加载时校验：

- 自身内容哈希；
- 绑定基础文件SHA-256和内部content hash；
- 六个契约完整且签名唯一；
- 三档、三型号、0至1数值范围、严格大于比较方式和90%完成门禁；
- 每个官方契约至少包含一个基础权重大于0的家族。

基础文件中的旧 `runtime_contracts` 物理保留以维持字节不变，但正式评分不再读取它们。

## 4. 概率数学

### 4.1 类别平滑

对每个格、每个模型、每个类别使用 `alpha=0.5`：

```text
p(category | model, cell)
  = (count + 0.5) / (total + 0.5 * category_count)
```

平滑防止可信采样中没出现过的合法类别产生零概率和负无穷似然。它不创造新答案，只防止小样本把“未观察到”误写成“绝对不可能”。

### 4.2 单格平均对数似然

待测格观测计数为 `n_c`，完成数为 `N`：

```text
L(model, cell) = sum_c n_c * ln p(c | model, cell) / N
```

未知合法答案映射到 `__OTHER__`，格式错误映射到 `__INVALID_OUTPUT__`。

### 4.3 家族合并

同一探针在多个请求格式格的分数先按格权重 w 做加权平均。一个探针家族的总权重取其适用格最大 w，上层再把三个家族贡献相加。

v4.1.1 只使用一次 w。旧实现曾先把分布向公共分布收缩，再用w合并，形成未经批准的二次降权；该层已在4.1.0末期删除，4.1.1继续保持单次权重。

### 4.4 匹配度

三个模型总分用 `T=1` 的 softmax 转成和为1的相对匹配度：

```text
match_m = exp(score_m) / sum_k exp(score_k)
```

这里没有tau、温度搜索、pass margin、alert margin、混合比例拟合、OOD百分位或Wilson回放门禁。

### 4.5 90%完整性门禁

每个计划探针格至少完成：

```text
ceil(planned * 0.90)
```

网络错误、取消或未分类输出不能贡献完成数。任一计划格不足90%，正式结果为证据不明确。连续监控以当前滚动窗口为planned。

### 4.6 强指向

正式资格还要求：

- config精确匹配官方预设；
- config hash和runtime signature与策略一致；
- 题面、developer、effort、normalizer、请求格式和上下文契约一致；
- 恰好一个模型严格超过该档阈值。

阈值：

| 档位 | Sol | Terra | Luna |
|---|---:|---:|---:|
| 低 | >0.54 | >0.58 | >0.77 |
| 中 | >0.82 | >0.84 | >0.97 |
| 高 | >0.98 | >0.97 | >0.99 |

等于阈值不通过。没有模型或多个模型越线都返回不明确。自定义配置不传decision policy，即使显示99.999%也不产生正式强指向。

## 5. 阈值标定

Stage C原实验5114条，本轮只使用三个正式探针相关的3840条可评分记录：国家1440、鸟1440、b80 960；7条格式无效按正式类别保留。

对每个真实模型分别随机重组为新单次档位：

- 低档每探针3次，1000万轮；
- 中档每探针10次，500万轮；
- 高档每探针、每适用格式格10次，100万轮。

在0.01网格中选取仍能让真实模型至少99%正确强指向的最高线。结果：

| 档位/模型 | 平均匹配度 | 1%分位 | 正式线 | 正确强指向 | 错误强指向 |
|---|---:|---:|---:|---:|---:|
| 低 Sol | 91.297% | 54.645% | >54% | 99.073840% | 0.260670% |
| 低 Terra | 92.842% | 58.805% | >58% | 99.091600% | 0.241680% |
| 低 Luna | 98.406% | 77.505% | >77% | 99.039430% | 0.073950% |
| 中 Sol | 93.658% | 82.995% | >82% | 99.269260% | 0 |
| 中 Terra | 94.532% | 84.835% | >84% | 99.257140% | 0 |
| 中 Luna | 99.452% | 97.135% | >97% | 99.126100% | 0 |
| 高 Sol | 99.214% | 98.645% | >98% | 99.992200% | 0 |
| 高 Terra | 98.529% | 97.505% | >97% | 99.883600% | 0 |
| 高 Luna | 99.877% | 99.365% | >99% | 99.763900% | 0 |

独立本地Plus正式池完整验证了Sol方向；历史Terra/Luna中档缺固定随机鸟，不能冒充新预设完整留出集。相同题面辅助池主要是 `effort=none`，没有复现正式 `low` 契约，证明请求契约会影响指纹。

## 6. 单次档位

低档19条：Juice high 5、low 2、输出48/32各1、覆盖1、国家/鸟/b80各3。

中档49条：Juice high 6、low/xhigh/max各3、输出48/32各1、覆盖2、国家/鸟/b80各10。

高档158条。四个profiles分别为47/37/37/37；固定32K和Native各74。b80只在普通无历史格运行10次。

修改任一参数后 `official=false`。恢复默认参数会重新匹配预设hash。

## 7. 持续监控

每周期每探针独立抽一次，命中后展开其全部适用profiles。低、中、高随机间隔分别为150–210、240–360、480–720秒；期望HTTP请求约3.5、4.0、14.5。

概率格按“探针 × profile”滚动，低/中/高窗口为3/10/20。Juice按effort滚动。输出完整性和覆盖检测当前摘要使用各自window；历史硬异常另存sticky event。概率指纹不粘住。

## 8. 申报模型与请求模型

`claimed_model`只能是三个标准型号，用于Juice、最终一致性和mismatch。`request_model`是非空自由文本，用于HTTP payload，拒绝控制字符。

SQLite schema 3在旧数据库上幂等增加request_model；旧值缺失时回退claimed_model。报告schema 4同时保存两个非敏感字段。恢复中断会话校验claimed、request、endpoint和config hash。

行为指纹本身不依赖申报。只有正式strong match与claimed不同，后端才输出 `fingerprint_claim_mismatch=true`；前端只消费该字段并变红，不自行猜测。

## 9. 上游传输

所有正式请求使用 Responses SSE。只有取得 `response.completed` 终态才成功；空回、截断、`response.failed`和`response.incomplete`独立分类。

普通请求默认UA由 `native-0.147.0.raw` 的User-Agent动态解析，避免第二份常量漂移。非空 `GPT56_USER_AGENT`只覆盖普通请求。Native请求继续使用原始模板完整头和body结构。

Python在每次Native请求前解析代理，顺序为NO_PROXY、HTTPS、ALL、HTTP、Windows手动代理、直连。只向Node传一个HTTPS_PROXY或完全不传代理。Node只执行现有HTTP CONNECT，不读取注册表。

Windows ProxyServer支持通用 `host:port` 和 `http=...;https=...`；ProxyOverride支持 `<local>`、精确主机和简单通配。PAC-only/SOCKS-only明确拒绝并提示HTTP/mixed或TUN。

Node stderr结构化错误被映射为中文：连接拒绝、DNS、CONNECT失败/超时、TLS、响应超时和401/403。代理userinfo绝不进入safe message、报告或留存。

## 10. Token估算

估算器不访问网络，也不引入tokenizer：

- 每条消息：`ceil(UTF-8字节/3)+8`；
- Juice取对应effort可用模板中最长UTF-8文本，不推进运行时随机数；
- Native每条加原始模板body字节/3；
- 固定32K每条加33792；
- 自定义探针使用其精确developer/user文本。

高档固定历史部分为 `74 × 33792 = 2,500,608`，总粗估还包含短题面和Native模板基础。持续模式按概率乘profile数计算每周期期望，不把window当请求量。

## 11. 持久化、取消和key

SQLite WAL由单writer串行写入；任务manifest冻结，job_id确定，累计最多3次HTTP尝试。重启后跳过已成功任务，并对running attempt对账。

停止通过共享取消控制器关闭普通响应socket或终止Native子进程，调度器每0.1秒检查取消，不执行 `shutdown(wait=True)`。

API key不持久化。检测运行结束后不自动清空，便于同一进程继续测试；session close和server shutdown清空。探针生成器仍在自身任务结束后清理key，这是独立生命周期。后台关闭只对仍在运行、停止中或仍有活跃线程的会话调用stop；complete、stopped、error和collected终态只关闭资源，不改写SQLite状态。

最近配置只恢复已经实际开始的SQLite会话。后端先执行 `normalize_config()` 并校验每个自定义探针签名；损坏或不兼容时回退单次低档并返回中文提示，不恢复原会话ID。正常完成、停止、错误只恢复配置；只有校验有效的interrupted配置恢复原session ID和剩余尝试预算。

探针生成器新导出的参考基线只保存类别统计、S、D、w和 `reference_ready`，不再写入废弃的 `runtime_contracts/formal_eligible`。读取端仍可导入旧文件，但不会据此授予正式评分资格。

## 12. 数据最小化与留存

默认结果保存规范化类别、答案SHA-256、长度和线路元数据，不保存认证信息。完整留存是显式开关，写入用户指定目录，包含完整请求/响应但仍省略Authorization。留存写失败时停止检测，避免产生不完整证据包。

## 13. 发行与测试

v4.1.1本地验收包括：

- 4.1.1专属契约测试；
- 检测器、概率、持久化、停止和生成器回归；
- Python编译和JavaScript/Node语法；
- 桌面与390px窄屏真实浏览器验收；
- 全新解压、无网络启动、假上游和Native假代理冒烟；
- 公开/内部允许清单与凭据、个人路径、缓存、数据库扫描。

可信答案分布在实施前后保持字节一致。

## 14. 参考资料

1. J. Lin, “Divergence Measures Based on the Shannon Entropy,” IEEE Transactions on Information Theory, 1991。用于理解Jensen–Shannon差异S与漂移D。
2. “One Token Is Enough: Model Fingerprinting with Low-Entropy Behavioral Distributions,” [arXiv:2607.10252](https://arxiv.org/html/2607.10252v1)。行为分布联合指纹和公开固定提示威胁模型参考。
3. “Deterministic or probabilistic?,” [arXiv:2502.19965](https://arxiv.org/abs/2502.19965)。语言模型随机选择存在系统偏差的实验背景。
4. 项目内 `GPT56_V4_2_PRESET_THRESHOLD_SIMULATION_REPORT_CN.md` 与两份2026-08-13 Monte Carlo产物。它们是4.1.1阈值的直接证据来源。

这些文献解释方法背景；最终实现细节和阈值权威仍是本项目冻结源码、基础指纹和4.1.1运行策略。
