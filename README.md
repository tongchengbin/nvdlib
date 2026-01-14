<div align="center">

# nvd (NVD API v2 CLI)

![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)
![NVD API](https://img.shields.io/badge/NVD-API%20v2-4B5563)
![Output](https://img.shields.io/badge/Output-json%20%7C%20jsonl-10B981)

</div>

基于 **NIST NVD API v2** 的命令行工具，用于查询 **CVE / CPE**。

> 参考 Python 项目 `vehemont/nvdlib` 的行为：默认限速、参数校验、输出拆分等。

## 🏷️ 徽章

请把下面的 `OWNER/REPO` 替换成你的 GitHub 仓库地址。

- CI: `https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg`
- Release: `https://github.com/OWNER/REPO/actions/workflows/release.yml/badge.svg`

## 🧭 目录

- [✨ 功能](#功能)
- [🚀 快速开始](#快速开始)
- [📦 安装](#安装)
- [🧪 用法](#用法)
- [🧾 输出格式](#输出格式)
- [📚 自动分页](#自动分页)
- [⏱️ API Key 与限速](#api-key-与限速)
- [🔁 CI/CD](#cicd)
- [❓ FAQ](#faq)

## ✨ 功能

- **CVE**
  - `cve get`：按 CVE ID 查询
  - `cve search`：按关键词/时间范围/严重性等查询
- **CPE**
  - `cpe search`：按关键词/匹配串/修改时间等查询
- **输出格式**
  - `--output json`：输出原始 API JSON
  - `--output jsonl`：列表按行输出，便于管道过滤
- **自动分页**
  - 当 `--limit > 2000` 时自动分页抓取并聚合（无需手动处理 `startIndex`）

## 🚀 快速开始

### 1) 构建

```bash
go build ./cmd/nvd
```

构建产物：

- Windows: `nvd.exe`
- Linux/macOS: `nvd`

### 2) 运行

```bash
./nvd --help
```

## 📦 安装

### 方式 A：从 GitHub Release 下载

当你打 tag（例如 `v0.1.0`）后，GitHub Actions 会自动构建并上传多平台二进制到 Release。

### 方式 B：从源码构建

```bash
git clone <your-repo>
cd <your-repo>
go build ./cmd/nvd
```

### 环境变量

- `NVD_API_KEY`：等价于 `--api-key`

## 🧪 用法

### 查看帮助

```bash
./nvd --help
./nvd cve --help
./nvd cpe --help
```

### CVE 示例

获取单个 CVE：

```bash
./nvd cve get --id CVE-2021-26855 --output json
```

关键字搜索（`jsonl` + 管道过滤）：

```bash
./nvd cve search --keyword exchange --limit 50 --output jsonl
```

按发布时间范围搜索（支持 RFC3339 或 `YYYY-MM-DD HH:MM`）：

```bash
./nvd cve search --pub-start "2022-02-10 00:00" --pub-end "2022-02-10 12:00" --output json
```

按 CVSSv3 严重性过滤：

```bash
./nvd cve search --keyword microsoft --cvss-v3-severity CRITICAL --limit 200 --output jsonl
```

### CPE 示例

关键词搜索：

```bash
./nvd cpe search --keyword ibm --limit 2000 --output jsonl
```

Windows 下配合 `findstr`：

```powershell
./nvd cpe search --keyword ibm --limit 2000 --output jsonl | findstr storage
```

## 🧾 输出格式

### `--output json`

输出 NVD API 的完整 JSON 响应（可配合 `--pretty` 美化）。

### `--output jsonl`

将列表结果按行输出：

- CVE：从 `vulnerabilities[].cve` 提取
- CPE：从 `products[].cpe` 提取

适合：

- `findstr/grep` 过滤
- 进入 `jq` 做二次处理
- 作为下游脚本输入

## 📚 自动分页

NVD API 单次响应通常有 `resultsPerPage` 上限。

本工具的策略是：

- `--limit <= 2000`：只请求一页
- `--limit > 2000`：自动分页（循环请求 `startIndex`），聚合到最多 `limit` 条

## ⏱️ API Key 与限速

NVD 官方建议脚本请求间隔数秒。

- **默认**：每次请求后 sleep 6 秒
- **有 API Key**：可通过 `--delay` 设定更低延迟（必须 `>= 0.6` 秒）

示例：

```bash
./nvd --api-key "$NVD_API_KEY" --delay 0.6 cpe search --keyword ibm --limit 5000 --output jsonl
```

## 🔁 CI/CD

本仓库内置 GitHub Actions：

- `.github/workflows/ci.yml`
  - push / PR 自动构建多平台产物并上传 artifacts
- `.github/workflows/release.yml`
  - 推送 `v*` tag 自动创建 Release 并上传二进制

## ❓ FAQ

### 1) 为什么查询很慢？

默认每次请求后 sleep 6 秒（符合 NVD 建议）。如果你有 NVD API Key，可以用 `--api-key` + `--delay 0.6` 加速。

### 2) `--limit` 真的能拉到 5000 吗？

可以。`--limit > 2000` 时工具会自动分页，多次请求聚合到最多 `limit` 条。

### 3) 为什么 `findstr` 有时匹配不到？

建议用 `--output jsonl`，每行一个对象，管道过滤更稳定。
