# 贡献指南（简体中文）

完整指南见根目录 [`CONTRIBUTING.md`](../../CONTRIBUTING.md)。

要点：仅使用 Go 1.26 标准库；绝不提交私钥；签名逻辑保留在 `internal/issuer`；
保持验证器 fail-closed 且不 panic；提交 PR 前运行 `gofmt`、`go vet`、`go build`、
`go test -race` 以及 fuzz 目标。

分支保护 / PR 流程：`main` 为受保护分支——所有改动均通过 feature/fix 分支的 PR
合入（禁止直接推送或强制推送），至少需要 1 个评审（单人维护者可在紧急情况下自行
合并，但需在 PR 留下审计说明），必须通过 CI 检查（`test`/`vet`/`vuln`/`lint` 及覆盖率
门槛），使用 squash 合并，生成的报告发布到源码历史之外而非提交到 `main`。详见根目录指南。
