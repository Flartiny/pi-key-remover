# pi-key-remover

一个用于 [Pi](https://github.com/earendil-works/pi-mono) 的敏感信息保护扩展。它会在用户消息进入会话和模型上下文之前识别 API key、token、密码与 private key，并替换成仍保留语义的占位符：

```text
OPENAI_API_KEY=sk-proj-……
↓
OPENAI_API_KEY=<secret:OPENAI_API_KEY>
```

扩展同时提供 `secret_exec` 工具：模型只需要在命令中引用 `$OPENAI_API_KEY`，扩展会从环境或模型上下文之外的本地 vault 注入实际值，并在工具输出进入上下文前再次脱敏。密钥值不需要出现在模型生成的命令中。

## 功能

- 在 Pi 的 `input` 阶段转换新用户消息，并在 `message_end` 阶段保护 template/skill 展开后的内容，原始 key 不写入会话。
- 在 `context`、system prompt 和最终 provider payload 阶段再次过滤，保护恢复的旧会话和其他上下文来源；图片 base64、thinking/reasoning 块与 provider opaque 字段不会作为文本改写。
- 对工具结果做二次脱敏，防止命令意外回显已知密钥。
- 高置信度密钥会全局匹配；`production` 等低熵密码只在敏感赋值或完整输出等明确上下文中替换，避免误伤普通文本。
- 识别常见 OpenAI、Anthropic、GitHub、GitLab、Google、AWS、Slack、Stripe、npm、PyPI、Hugging Face key，JWT、Bearer token、webhook URL、URL 密码、PEM private key，以及 `*_API_KEY` / `*_TOKEN` / `*_SECRET` / `*_PASSWORD` 等赋值。
- 同一密钥使用稳定的具名占位符；已生成的占位符在多层生命周期过滤中保持不变，不会被重复识别或嵌套。
- 默认将用户粘贴的密钥保存到项目隔离、权限为 `0600` 的用户级 vault；不会把 vault 放进 Git 工作树。
- 从 `.env` / `.env.local` 安全解析变量（只解析，不 `source`，不会执行文件内容）。
- 提供 `/key-remover` 指令，可通过参数补全切换保护、切换 capture、查看状态或重新加载环境。

## 安装

在本仓库中直接试用：

```bash
pi -e ./src/index.ts
```

作为本地 Pi package 安装：

```bash
pi install /absolute/path/to/pi-key-remover
```

安装后重启 Pi。开发时修改扩展可执行 `/reload`。

## 使用

### 1. 直接粘贴并自动保护

输入：

```text
DEPLOY_API_TOKEN=example-value，请用它查询仓库。
```

模型实际看到：

```text
DEPLOY_API_TOKEN=<secret:DEPLOY_API_TOKEN>，请用它查询仓库。
```

默认情况下，扩展把实际值写入用户级 vault，并在当前会话中把它作为 `DEPLOY_API_TOKEN` 提供给 `secret_exec`。

### 2. 推荐：预先放入环境文件

在项目的 `.env` 或 `.env.local` 中写入：

```dotenv
GITHUB_TOKEN="example"
```

不要把 `.env` 提交到 Git。启动或执行 `/key-remover reload` 后，可以只告诉模型：

```text
请使用 <secret:GITHUB_TOKEN> 查询 GitHub API。
```

模型可调用：

```text
secret_exec({
  command: "curl -H \"Authorization: Bearer $GITHUB_TOKEN\" https://api.github.com/user",
  secrets: ["GITHUB_TOKEN"]
})
```

`secret_exec` 只按名称选择变量，命令文本和模型上下文中都不需要出现实际 key。默认执行前会向用户展示命令和变量名并要求确认；扩展还会在返回结果中替换任何原样回显的已选择密钥。

### 快捷指令

```text
/key-remover          # 查看状态（默认动作）
/key-remover status   # 查看状态
/key-remover toggle   # 切换输入与上下文过滤
/key-remover capture  # 切换是否自动保存粘贴的密钥
/key-remover reload   # 重新读取配置、.env、进程环境和 vault
```

在交互界面输入 `/key-remover` 并键入空格后，会显示参数补全和说明。保护开关与 capture 开关状态保存在 Pi session 的非上下文 custom entry 中，恢复会话时会恢复。

> 保护状态切换为 OFF 后，后续原始消息可以进入会话和模型。`secret_exec` 自身仍始终对输出做脱敏，以避免它变成明文泄漏通道。

## 配置

可信项目可创建 `.pi/key-remover.json`：

```json
{
  "enabled": true,
  "capturePastedSecrets": true,
  "envFiles": [".env", ".env.local"],
  "maxOutputBytes": 51200,
  "confirmSecretExec": true,
  "allowHeadlessSecretExec": false
}
```

可选字段：

- `enabled`：新会话默认是否启用。
- `capturePastedSecrets`：是否把从消息中截获的密钥持久化；默认 `true`。
- `envFiles`：相对项目目录或绝对路径的 dotenv 文件。仅可信项目会读取。
- `vaultPath`：自定义 vault 路径；支持 `~` 和 `{projectHash}`。相对路径以项目目录解析。
- `maxOutputBytes`：`secret_exec` 返回给上下文的最大字节数，范围 1–50 KiB；同时固定最多 2000 行。
- `confirmSecretExec`：每次运行前是否显示命令和变量名并要求确认；默认 `true`。
- `allowHeadlessSecretExec`：没有 UI 且需要确认时是否仍允许执行；默认 `false`。仅应在可信自动化环境中开启。

默认 vault 路径形如：

```text
~/.pi/agent/pi-key-remover/<project>-<cwd-hash>.env
```

默认专用目录权限为 `0700`，vault 文件权限为 `0600`。自定义 `vaultPath` 时扩展不会修改现有父目录权限。

变量冲突时优先级为：`process.env` > vault > 后加载的 `envFiles` > 先加载的 `envFiles`。当前会话中新粘贴的值会立即覆盖内存中的同名值。

## 安全边界

- 扩展使用规则匹配，不可能识别所有无标签、无固定格式的随机秘密。建议使用明确的环境变量名。
- 图片中的文字不会 OCR；图片内的 key 不在本扩展的文本过滤范围内。
- 为避免破坏 provider 签名，thinking、reasoning 和 redacted thinking 块始终原样保留，其中出现的 key 不会被本扩展改写。
- `secret_exec` 与 Pi 的 shell 工具一样拥有本机执行权限，只应安装可信代码并审查确认框中的命令。无 UI 模式默认拒绝执行。
- `secret_exec` 子进程仅继承运行所需的基础环境变量和显式选择的秘密，不会继承其他 ambient credential。
- 输出过滤能阻止密钥原文回显，但无法可靠阻止恶意命令先对密钥做编码、分片、哈希或通过网络发送。不要在不可信提示下授权敏感操作。
- 扩展只能保护加载后的请求。已经发送给远程 provider、终端日志或其他外部系统的秘密无法追溯撤回，应立即轮换。
- vault 是权限受限的明文本地文件，不是系统 keychain。需要更高安全等级时，请关闭自动 capture，并通过进程环境或专用 secret manager 注入变量。

## 开发

```bash
npm install
npm run check
```

测试覆盖 key/token 识别、上下文保持、dotenv 安全解析、vault 权限、会话开关，以及 `secret_exec` 注入和输出脱敏。
