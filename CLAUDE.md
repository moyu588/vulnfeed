# CLAUDE.md — vulnfeed 项目记忆

> 本文件是持久化记忆（原 `/openclaw/github/AGENTS.md`，已并入此处），新会话请先读这里再动手。详细文档见文末索引。

## 项目拓扑

- `vulnfeed/`（本仓库）— 二开源码仓库（Rust，入口 `src/cli.rs`，含 `sqlx::migrate!` 启动时自动迁移）
  - `origin` = `git@github.com:moyu588/vulnfeed.git`（SSH Deploy Key：`/openclaw/github/.ssh/id_ed25519_vulnfeed`，仓库已配 `core.sshCommand`）
  - `upstream` = `https://github.com/fan-tastic-z/vulnfeed.git`
  - 分支策略：`main` 镜像上游保持干净；`dev` 为二开分支（含自定义改动 + 文档）
  - 2026-09-02 核查：上游 `main` = 本地 `main` = `0256bcd`，无待合并更新
  - 注：本地 `main` 实际跟踪 `origin/main`（同步方案 §7 所写 "跟踪 upstream/main" 与现状不符，以实际为准；不影响手动 `merge upstream/main` 流程）
- `../vulnfeed-deploy/` — **生产环境**（docker compose）
  - `postgres:14.0` + `vulnfeed:latest`（镜像由本仓库 `Dockerfile` 构建）
  - **生产数据在 `../vulnfeed-deploy/data/`**（bind mount 到 postgres 数据目录）
  - 配置 `../vulnfeed-deploy/config/config.toml`，两个配置文件均 `chmod 600`

## 开发工作流（用户需求，务必遵循）

1. **二开只在本地 `dev` 分支进行**，提交后推送到 `origin`（fork 仓库）保存：`git push origin dev`
2. **持续关注上游 `upstream/main` 的功能更新**，有更新时合并到本地：
   - 查上游状态：因 git smart-HTTP 挂死问题，用 GitHub API（`https://api.github.com/repos/fan-tastic-z/vulnfeed/branches/main`）对比本地 `main` 的 commit sha
   - 拉取上游：走 SSH 或先排查代理；同步流程详见 `docs/二开与上游同步方案.md`
   - **统一走本地 `upstream` 命令行同步，禁用 GitHub "Sync fork" 按钮**——两条路二选一，不可混用
   - 合并前先备份：`git branch dev-backup-$(date +%Y%m%d)`；合并完打标记：`git tag synced-$(date +%Y%m%d)`
   - 合并路径：`upstream/main` → 本地 `main`（快进，保持干净）→ `git push origin main`（同步 fork 的 main）→ `merge main` 到 `dev`（冲突处理见同步方案 §5）→ `git push origin dev`
   - 合并后必查：`git diff main..dev -- migrations/ dev/config.toml.example`，确认迁移仍为增量、且无新增必填配置项（见生产红线 §2）
3. **`main` 不直接提交二开改动**，仅作为上游镜像与合并中转；较大的二开功能可从 `dev` 切 `feat-xxx` 分支，做完合回 `dev`

## ⚠️ 生产红线（务必遵守）

**0. 生产禁区清单（2026-09-08 用户确认）**：**9000 端口、5432 端口、`../vulnfeed-deploy/data/`、`vulnfeed-net` Docker 网络、生产容器**（`vulnfeed`、`postgres`）。测试验证一律在 `../vulnfeed-test/` 进行，测试服务须绑定内网可达的**非 9000/5432** 端口（隔离与内网访问总原则见用户级 `~/.claude/CLAUDE.md` §2–3，不在此重复）。

1. 数据只在 `../vulnfeed-deploy/data/`。升级 = 只重建 `vulnfeed` 应用容器，**绝不**动 postgres 容器和 data 目录。
2. 应用启动时自动执行数据库迁移（`src/cli.rs` 中 `sqlx::migrate!`），**迁移只进不退**。升级前必查：`git diff main..HEAD -- migrations/ dev/config.toml.example`——若出现删列/改类型等非增量迁移，回滚旧镜像会失败；若新增必填配置项，旧 `config.toml` 会导致启动失败（服务挂但数据无损）。
3. 标准升级流程（详见运维备忘）：
   `pg_dump` 备份 → `docker tag` 旧镜像留回滚点 → `docker build` → `docker compose up -d vulnfeed`（仅应用）→ 验证迁移日志 + `curl http://127.0.0.1:9000/` 返回 200（应用容器端口为 **9000**）。
4. 安全整改已于 2026-08-28 完成并复测通过：数据库密码、JWT 密钥已换强随机值，5432 端口收敛到 `127.0.0.1`，配置文件 600；admin 密码经用户 2026-09-02 手动登录验证确认已改——**6 项整改全部闭环**，不要回退这些安全配置。记录在 `../vulnfeed-deploy/密码与暴露面整改方案.md` §6。

## 已知环境问题

- ~~git smart-HTTP 到 github.com 会挂死~~ **已解决（2026-09-07）**：根因是 `~/.bashrc` 的代理变量为小写（`http_proxy=http://10.10.2.14:7890`）且仅交互式 shell 生效，非交互进程调 git 拿不到。已写入 git 全局配置：`git config --global http.https://github.com.proxy http://10.10.2.14:7890`（仅对 github.com 生效），`git ls-remote`/`fetch` HTTPS 直连已验证可用。同步上游可直接走 HTTPS，不再必须绕 SSH；GitHub API 查状态的方式仍可用。
- 低危遗留（无害，勿花时间修）：容器内 `pg_hba` trust 免密条目、`POSTGRES_USERNAME` 应为 `POSTGRES_USER`（笔误）。

## 详细文档索引

| 文档 | 内容 |
|---|---|
| `docs/二开与上游同步方案.md` | 多远端同步流程 + 冲突处理 + 执行记录 |
| `docs/生产升级与运维备忘.md` | 镜像升级完整手册：备份/构建/发布/验证/回滚命令 |
| `../vulnfeed-deploy/密码与暴露面整改方案.md` | 安全整改方案 + §6 复测记录 |
