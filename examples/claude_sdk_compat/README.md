# Claude Agent SDK / GLM compatibility demo

独立、固定输入、无工具执行的兼容性样例。用于评估 SDK 接口与记录格式；没有接入 Mako 的任务执行、目标访问或调度逻辑，也没有修改 Mako。

## 安装与运行

```bash
cd examples/claude_sdk_compat
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/python demo.py
```

默认运行真实 Claude Agent SDK 和它自带的 CLI，但模型服务由本机 `mock_server.py` 模拟。模拟服务不转发请求；报告中 `mode` 为 `mock`，不能据此认定 GLM 服务可用。

检查任务由 `demo.py` 中的 `CASES` 和 `SCHEMA` 定义：固定文本响应与简单 JSON 计算。JSON 是模型文本经本地 schema 校验，不是 SDK 原生 `output_format` 测试。模拟服务记录请求中实际携带的工具数量，非零时检查失败。

## 真实服务验证

复制 `.env.example` 为 `.env`，填写新密钥并核对代理配置，然后运行：

```bash
.venv/bin/python demo.py --live --env-file .env
```

认证类型由 `GLM_AUTH_MODE` 选择，取值见 `.env.example`；应以代理的接口文档为准。进程环境变量优先于指定的 env 文件。此程序不自动读取 Mako 或用户目录的 `.env`，不使用 `GLM_BASE_URL`，也不回退到已有 Claude 登录。真实模式需要 HTTPS。

`--live` 会把固定示例提示词和认证信息发送到配置的代理。请填写自己的代理地址并确认模型名；尚未完成真实服务验证。Anthropic 官方不支持经网关路由到非 Claude 模型，代理兼容性需要独立确认。

## 输出与边界

报告默认写入 `results/`，每次使用新文件名。可用 `--output` 指定目录，`--timeout` 设置每个检查的超时。成功退出码为 0，检查失败为 1，配置错误为 2。报告记录模式、模型、事件类型、结果和用量；不保存原始 stderr 或异常正文。

每次检查使用临时工作区和独立 SDK 配置目录；关闭内置工具、外部 MCP、项目/用户设置加载，并通过 hook 拒绝工具调用。它不是恶意代码隔离沙箱。SDK 或系统的管理级策略仍可能影响行为。

通过这些检查，只能证明对应的文本/JSON往返。工具调用、会话恢复、上下文压缩、SDK 原生结构化输出和 Mako 迁移均不在验证范围内。模拟模式的 token 用量是合成数据，不代表实际价格或开销。

## 验证

```bash
.venv/bin/python -m unittest -v
.venv/bin/python demo.py
```

测试覆盖错误结果、缺少结束事件、意外工具请求、敏感错误正文、超时、JSON 不符合 schema、配置优先级和缺失凭据。

依赖版本以 `requirements.txt` 为准；全量已安装依赖可查看 `requirements.lock.txt`。运行选项以 `demo.py --help` 为准。

参考：[SDK Python 接口](https://code.claude.com/docs/en/agent-sdk/python)、[网关支持边界](https://code.claude.com/docs/en/llm-gateway)。
