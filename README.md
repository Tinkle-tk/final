# 工控设备固件漏洞自动化提取与知识库构建

本项目是一个面向工控设备固件漏洞信息的自动化系统，提供以下能力：

- 爬虫采集漏洞公告链接（Scrapy）
- PDF/HTML 文本解析（pdfplumber + BeautifulSoup）
- 漏洞字段抽取（规则+NLP）
- MySQL 知识库存储（Flask + SQLAlchemy）
- RESTful API 查询与导入
- Vue 前端图形化查询
- Docker 一键部署

## 1. 目录结构

```text
E:\final
├─ backend
│  ├─ app
│  │  ├─ crawlers
│  │  ├─ extractors
│  │  ├─ routes
│  │  ├─ services
│  │  ├─ config.py
│  │  ├─ extensions.py
│  │  └─ models.py
│  ├─ tests
│  ├─ run.py
│  ├─ ingest_file.py
│  ├─ requirements.txt
│  └─ Dockerfile
├─ frontend
│  ├─ src
│  ├─ package.json
│  ├─ vite.config.js
│  └─ Dockerfile
├─ sql
│  └─ init_schema.sql
├─ docker-compose.yml
└─ README.md
```

## 2. 环境要求（必须）

### 2.1 操作系统

- Windows 10/11
- Ubuntu 20.04+
- macOS 12+

### 2.2 运行时版本

- Python: 3.11.x（推荐）
- Node.js: 20.x（推荐）
- npm: 10.x+
- MySQL: 8.0+（推荐 8.4）
- Docker Desktop: 4.0+
- Docker Compose: v2+

说明：
- 项目后端依赖中包含 `Flask==3.1.0`、`Scrapy==2.12.0`，建议按上述版本运行，兼容性最好。

## 3. 依赖与插件清单

### 3.1 Python 依赖（后端）

见 [backend/requirements.txt](E:/final/backend/requirements.txt)：

- Flask
- Flask-SQLAlchemy
- PyMySQL
- pdfplumber
- beautifulsoup4
- Scrapy
- requests
- pytest

### 3.2 前端依赖

见 [frontend/package.json](E:/final/frontend/package.json)：

- vue 3
- vite
- axios

### 3.3 可选插件/工具（强烈建议）

这些不是项目必须，但对开发、调试、答辩演示非常有帮助：

- API 调试：Postman 或 Apifox
- 数据库可视化：MySQL Workbench / DBeaver
- 前端调试：Chrome DevTools
- 代码编辑器：VS Code
- VS Code 推荐插件：
  - Python（ms-python.python）
  - Pylance（ms-python.vscode-pylance）
  - Vue - Official（Vue.volar）
  - ESLint（dbaeumer.vscode-eslint）
  - Docker（ms-azuretools.vscode-docker）
  - REST Client（humao.rest-client）

### 3.4 OCR 可选组件（处理扫描版 PDF 时）

本项目当前默认处理“可复制文本 PDF”。若要支持扫描件，需要安装：

- Tesseract OCR
- Python 包：pytesseract、opencv-python（可后续扩展时再安装）

## 4. 部署方式 A：Docker 一键部署（推荐答辩使用）

### 4.1 前置检查

```bash
docker --version
docker compose version
```

### 4.2 启动

在项目根目录 `E:\final` 执行：

```bash
docker compose up --build
```

### 4.3 访问地址

- 前端页面：[http://localhost:5173](http://localhost:5173)
- 后端健康检查：[http://localhost:5000/health](http://localhost:5000/health)
- MySQL 端口：`3306`

### 4.4 停止

```bash
docker compose down
```

如需清理数据库卷：

```bash
docker compose down -v
```

## 5. 部署方式 B：本地开发部署（不使用 Docker）

### 5.1 启动 MySQL

1. 安装 MySQL 8.x。
2. 创建数据库：

```sql
CREATE DATABASE ics_vuln_kb DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

3. 可选：执行 [sql/init_schema.sql](E:/final/sql/init_schema.sql) 手动建表。

### 5.2 启动后端

```bash
cd backend
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

安装依赖：

```bash
pip install -r requirements.txt
```

配置环境变量（示例）：

```env
DATABASE_URL=mysql+pymysql://root:root@localhost:3306/ics_vuln_kb?charset=utf8mb4
FLASK_ENV=development
```

启动后端：

```bash
python run.py
```

### 5.3 启动前端

```bash
cd frontend
npm install
npm run dev
```

如果后端不在 `localhost:5000`，设置：

```env
VITE_API_BASE_URL=http://你的后端地址:5000
```

## 6. 运行流程（建议演示顺序）

1. 打开前端页面。
2. 在“文档导入（文本）”粘贴漏洞公告内容并导入。
3. 在“漏洞查询”按 `CVE`、`厂商`、`型号`检索。
4. 点击“查补丁”查看修复方案。

示例文本可用 [backend/sample_advisory.txt](E:/final/backend/sample_advisory.txt)。

## 7. API 清单

### 7.1 查询漏洞

```http
GET /vulnerabilities?cve_id=&product_name=&vendor=
```

### 7.2 查询某产品受影响漏洞

```http
GET /products/{product_id}/affected_vulnerabilities
```

### 7.3 查询漏洞相关补丁

```http
GET /vulnerabilities/{cve_id}/related_patches
```

### 7.4 导入漏洞文本

```http
POST /vulnerabilities/ingest
Content-Type: application/json

{
  "text": "Siemens S7-1200 ... CVE-2024-12345 ...",
  "hints": {
    "vendor": "Siemens",
    "series": "S7",
    "model": "S7-1200",
    "upgrade_path": "升级到 v4.5.2"
  }
}
```

## 8. 爬虫运行

```bash
cd backend/app/crawlers
scrapy crawl vendor_advisory -O advisories.json
```

说明：
- 需要在 [vendor_advisory_spider.py](E:/final/backend/app/crawlers/ics_spider/spiders/vendor_advisory_spider.py) 配置 `start_urls`。

## 9. 测试与校验

后端测试：

```bash
cd backend
pytest -q
```

健康检查：

```bash
curl http://localhost:5000/health
```

返回：

```json
{"status":"ok"}
```

## 10. 常见问题排查

1. `ModuleNotFoundError`
- 原因：虚拟环境未激活或依赖未安装。
- 解决：激活 `.venv` 后重新 `pip install -r requirements.txt`。

2. MySQL 连接失败
- 原因：`DATABASE_URL` 用户名/密码/端口错误，或 MySQL 未启动。
- 解决：检查连接串，确认 3306 已监听。

3. 前端调用后端跨域问题
- 当前默认通过本地地址直连，如果你改了域名/端口，需要在后端加 CORS 配置。

4. PDF 提取为空
- 原因：扫描版 PDF 不是文本层。
- 解决：接入 Tesseract OCR（见 3.4）。

5. Docker 启动慢
- 原因：首次拉取镜像和安装依赖。
- 解决：耐心等待；后续重建会更快。

## 11. 毕设提交建议（可选）

- 提交时附带：
  - 运行录屏（导入-查询-补丁查询）
  - API 测试截图（Postman）
  - 数据库表结构截图（Workbench）
- 论文中可引用本 README 的“环境配置”和“部署步骤”章节。
## 12. NLP + 大模型抽取配置

项目当前支持 4 种抽取模式：

- `rule`：纯规则抽取（正则 + 关键词）
- `llm`：纯大模型抽取（结构化 JSON 输出）
- `hybrid`：规则 + 大模型融合（推荐）
- `auto`：自动模式（优先融合，失败回退规则）

### 12.1 环境变量

后端 `.env` 可配置：

```env
EXTRACTOR_MODE=hybrid
LLM_MODEL=gpt-4.1-mini
LLM_BASE_URL=
LLM_API_KEY=
```

### 12.2 API 调用示例

```http
POST /vulnerabilities/ingest
Content-Type: application/json

{
  "text": "...",
  "extractor_mode": "hybrid",
  "hints": {
    "vendor": "Siemens",
    "series": "S7",
    "model": "S7-1200"
  }
}
```

返回中会包含实际使用模式：

```json
{
  "records": 3,
  "inserted": 2,
  "updated": 1,
  "extractor_mode": "hybrid"
}
```
