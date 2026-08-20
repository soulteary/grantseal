# 贡献指南（简体中文）

完整指南见根目录 [`CONTRIBUTING.md`](../../CONTRIBUTING.md)。

要点：仅使用 Go 1.26 标准库；绝不提交私钥；签名逻辑保留在 `internal/issuer`；
保持验证器 fail-closed 且不 panic；提交 PR 前运行 `gofmt`、`go vet`、`go build`、
`go test -race` 以及 fuzz 目标。
