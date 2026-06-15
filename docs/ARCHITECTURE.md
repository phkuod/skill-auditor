# skill-auditor — 完整設計與架構（Design & Architecture）

**版本**：v1（已實作，已合併 master）
**狀態**：77 tests pass（1 skipped：symlink 測試需 OS 支援）· coverage 94% · 安全不變式（never executes audited code）已由最終審查確認
**相關文件**：設計規格 `docs/superpowers/specs/2026-06-13-skill-auditor-design.md`、實作計畫 `docs/superpowers/plans/2026-06-13-skill-auditor.md`、使用說明 `README.md`

---

## 1. 概觀（Overview）

**一句話**：一個靜態優先、LLM 加值的 AI Agent，稽核從網路下載的 Agent Skill 是否含安全問題，輸出分級報告與修復建議，**全程絕不執行被稽核 skill 的任何程式碼**。

從網路下載的 Agent Skill（`SKILL.md` + markdown 規則、Python/shell 腳本、assets、可能含 hooks）在安裝前無從得知是否安全。攻擊面包含：腳本裡的破壞性/外洩程式碼、`SKILL.md` 針對 AI 的 prompt injection、過度授權 frontmatter、混淆程式碼、描述與實際行為不符。本工具讓使用者或市集後端在安裝/收錄前先做自動稽核，得到可信、可重現、附修復建議的報告。

### 設計支柱（兩條安全不變式）

| 支柱 | 內容 | 落實 |
|------|------|------|
| **A. 絕不執行被稽核程式碼** | 純靜態讀取 + 解析；不 sandbox、不動態執行 | `read_text`、`ast.parse`、regex、`yaml.safe_load`；API zip 解壓後僅掃描；無 `subprocess`/`import`/`exec` skill 內容 |
| **B. 稽核器自身不可被劫持** | 不可信文字餵 LLM，靜態層兜底 | skill 文字包在 `<skill_file>` 標籤當作資料；LLM 無行動工具、只吐 `Finding[]`；`markdown_injection` 靜態規則即使 LLM 被騙仍標記注入 |

---

## 2. 設計目標與原則

- **library-first**：整個產品是一個純函式 `audit_skill(path, *, use_llm=True, agent=None) -> AuditReport`；CLI 與 Web API 只是其薄轉接層。
- **確定性優先**：靜態掃描永遠執行、可離線、CI 友善，是報告骨幹；LLM 是獨立加值層。
- **優雅降級**：缺 API key 或免費模型全失敗時，自動退回靜態報告並於 `notes` 註記，`llm_used=False`。
- **單一職責、可獨立測試**：`inventory` 只分類、`scanners/*` 各管一類規則、`engine` 只編排、`report` 只算 verdict 與渲染、轉接層只做 I/O。
- **結構化輸出**：不輸出自由文字；一切都是 Pydantic 模型（`Finding` / `AuditReport`）。
- **不自建排程**：定期重審交給 cron / CI / skill-manager 呼叫 CLI/API。

### 已定案決策

| 決策點 | 選擇 |
|--------|------|
| 偵測方式 | 混合：靜態掃描（regex + Python `ast`）+ LLM 推理 |
| 流程取向 | 確定性管線 + 優雅降級：靜態層永遠跑，LLM 層獨立可跳過 |
| 執行安全 | 純靜態，絕不執行被稽核 skill 的任何程式碼 |
| 技術棧 | Python 3.11+、PydanticAI、OpenRouter `FallbackModel` 免費模型、FastAPI、內建 `ast`、`rich`、PyYAML、`uv` |
| v1 交付 | 核心 library + CLI + 薄 Web API |
| 輸出 | 分級報告（CRITICAL/HIGH/MEDIUM/LOW/INFO）+ 修復建議 + exit code + 可選 JSON |
| 排程 | 不自建，交給外部定時呼叫 |

---

## 3. 系統架構（分層與相依）

![skill-auditor 系統架構圖](architecture-diagram.svg)

> 圖檔：`docs/architecture-diagram.svg`（向量，可縮放編輯）· `docs/architecture-diagram.png`（點陣，方便預覽）

```
        ADAPTERS（薄 I/O 轉接層）
        ┌──────────────┐        ┌──────────────────────────────┐
        │  cli.py       │        │  api.py  (FastAPI)            │
        │  __main__.py  │        │  POST /audit · GET /rules     │
        │  argparse     │        │  GET /health · zip-slip 防護  │
        └──────┬───────┘        └───────────────┬──────────────┘
               │   兩者只呼叫 ↓                   │
        ───────┴──────────────── ENGINE ─────────┴────────────────
                          ┌────────────────────┐
                          │ engine.audit_skill()│  編排 + 優雅降級
                          └──┬───────┬───────┬──┘
              ┌──────────────┘       │       └──────────────┐
              ▼                      ▼                      ▼
      ┌──────────────┐    ┌────────────────────┐    ┌──────────────┐
      │ inventory.py │    │ scanners/           │    │ llm/          │
      │ 走訪 + 分類   │    │  __init__:run_all,  │    │  agent.py     │
      │ （唯讀）      │    │          RULES      │    │  （抗注入     │
      └──────┬───────┘    │  python_ast         │    │   SYSTEM_PROMPT│
             │            │  shell              │    │   FallbackModel│
             │            │  markdown_injection │    │   /free models）│
             │            │  frontmatter        │    │  stages.py     │
             │            │  obfuscation_secrets│    │  semantic_scan │
             │            └─────────┬──────────┘    └──────┬───────┘
             │  每個掃描器：scan(files)->Finding[]          │
             └──────────────┬──────┴───────────┬───────────┘
                            ▼                  ▼
                  ┌──────────────────┐  ┌──────────────┐
                  │  report.py        │  │  models.py    │ Severity/Source
                  │  verdict/counts/  │  │  (Pydantic)   │ Finding/AuditReport
                  │  exit/rich render │  └──────────────┘ ← 全模組共用
                  └──────────────────┘
                  ┌──────────────┐
                  │  config.py    │  .env、FREE_MODELS、可選 key
                  └──────────────┘

  相依規則：adapters → engine → {inventory, scanners, llm, report}；
  所有模組 → models。無向上相依、無循環。掃描器統一介面、可插拔。
```

---

## 4. 執行流程（控制 + 資料流）

```
  skill dir / .zip
        │  cli.py / api.py（解析參數 / 安全解壓）
        ▼
  engine.audit_skill(path, use_llm, agent)
        │
        ▼
  1) inventory_skill(dir) ─► list[SkillFile](path, relpath, kind, text)   唯讀走訪
        │                    分類：skill_md/python/shell/markdown/config/asset
        ▼
  2) scanners.run_all(files) ─► list[Finding]   ◄── 確定性骨幹，永遠執行
        │     python_ast · shell · markdown_injection · frontmatter · obfuscation_secrets
        │     (source=static, confidence=1.0)
        │
        ├─ use_llm == False ───────────────────────────────┐
        │                                                   │
        ▼ use_llm == True                                   │
  agent = 注入 | build_model()→Agent                        │
        │                                                   │
        ├─ None（無 key） ─► note "LLM skipped" ───────────┤
        │                                                   │
        ▼ Agent                                             │
  3) semantic_scan(agent, files)                            │
        │   skill 文字包進 <skill_file> 當「不可信資料」      │
        │   agent.run_sync → Finding[] (source=llm)         │
        │   try/except → 任一模型錯誤回 []（降級）           │
        │                                                   │
        ├─ 有 findings ─► extend, llm_used=True             │
        ├─ [] / 失敗  ─► note + llm_used=False              │
        │                                                   │
        ▼◄──────────────────────────────────────────────────┘
  4) build_report(...)
        │   compute_verdict： 任一 CRITICAL→block；否則任一 HIGH→warn；否則 pass
        │   依 severity 排序、counts、附 notes
        ▼
  AuditReport
        │
        ▼
  render_report (rich) | model_dump_json | exit code(pass=0 warn=1 block=2，--fail-on 可調)
```

**每條路徑都成立**：skill 內容只被「讀取 + 解析」或當「文字」傳給 LLM，從不被 import / eval / 執行。

---

## 5. 模組職責

| 模組 | 職責 | 對外介面 |
|------|------|----------|
| `models.py` | 結構化輸出型別 | `Severity`、`Source`、`Finding`、`AuditReport` |
| `config.py` | 可選 API key 載入、免費模型清單 | `API_KEY_ENV_VAR`、`FREE_MODELS`、`load_api_key()` |
| `inventory.py` | 唯讀走訪 skill 目錄、分類檔案 | `SkillFile`、`classify()`、`inventory_skill()` |
| `scanners/python_ast.py` | AST 分析 Python：執行/網路/密鑰路徑 | `scan(files)`、`DANGEROUS_CALLS`、`DANGEROUS_ATTR_CALLS` |
| `scanners/shell.py` | 正則掃 shell/markdown 危險指令 | `scan(files)`、`RULES` |
| `scanners/markdown_injection.py` | 啟發式偵測 prompt injection | `scan(files)`、`PATTERNS` |
| `scanners/frontmatter.py` | SKILL.md YAML 過度授權/hooks | `scan(files)` |
| `scanners/obfuscation_secrets.py` | 混淆 + 寫死密鑰 | `scan(files)`、`SECRET_RULES` |
| `scanners/__init__.py` | 掃描器註冊表 + 規則型錄 | `run_all(files)`、`RULES` |
| `report.py` | verdict 邏輯、counts、exit code、rich 渲染 | `compute_verdict()`、`build_report()`、`verdict_exit_code()`、`render_report()` |
| `llm/agent.py` | 抗注入 PydanticAI agent、FallbackModel | `SYSTEM_PROMPT`、`build_model()`、`build_audit_agent()` |
| `llm/stages.py` | 語意掃描 + 結構化容錯 | `LlmFindings`、`semantic_scan()` |
| `engine.py` | 管線編排 + 優雅降級 | `audit_skill()` |
| `cli.py` / `__main__.py` | CLI 轉接層 | `main(argv)` |
| `api.py` | FastAPI app | `app`、`/audit`、`/rules`、`/health` |

---

## 6. 資料模型（Pydantic）

```python
class Severity(str, Enum):
    CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

class Source(str, Enum):
    STATIC="static"; LLM="llm"

class Finding(BaseModel):
    rule_id: str          # 例 "PY-EXEC-001"（min_length=1）
    category: str         # 風險類別（見 §7）
    severity: Severity
    title: str
    file: str             # 相對 skill 根目錄路徑
    line: int | None = None
    evidence: str = ""    # 截斷的問題片段
    explanation: str = "" # 為何危險
    remediation: str = "" # 如何修
    source: Source = Source.STATIC
    confidence: float = 1.0   # 0..1（靜態=1.0）

class AuditReport(BaseModel):
    skill_name: str
    skill_path: str
    verdict: str          # "block" | "warn" | "pass"
    findings: list[Finding]
    counts: dict[str, int]
    llm_used: bool
    notes: list[str] = []
```

**Verdict**：任一 `CRITICAL` → `block`；否則任一 `HIGH` → `warn`；否則 `pass`。
**Exit code**：`block`=2、`warn`=1、`pass`=0；`--fail-on {critical|high|medium}` 調整 CLI 在哪個門檻回非零。

---

## 7. 掃描器與規則型錄（系統核心，共 42 條靜態規則）

每條規則有唯一 `rule_id`，由 `scanners.RULES` 統一登錄（供 `GET /rules` 查詢）。

### 風險類別

| 類別 | 掃描器 | 偵測內容 |
|------|--------|----------|
| `RCE_SUPPLY_CHAIN` | python_ast / shell | `eval`/`exec`/`compile`/`__import__`/`importlib.import_module`、`subprocess`、`os.system`、`pickle.loads`、`curl\|bash` |
| `DESTRUCTIVE` | shell / python_ast | `rm -rf`、`shutil.rmtree`、`os.remove`/`unlink`/`rmdir`、`Path.unlink`、`dd`、`mkfs`、`git push --force` |
| `EXFILTRATION` | python_ast | 對外網路（`requests`/`urllib`/`httpx`/`socket`）+ 讀取 `~/.ssh`/`.env`/credentials 等敏感路徑 |
| `FILESYSTEM` | filesystem | path traversal（`../`）、`open()` 寫入絕對路徑（逃出 skill 目錄） |
| `PROMPT_INJECTION` | markdown_injection | 「ignore previous instructions」、偽 `SYSTEM:` 標頭、「if you are an AI…」、誘導裁決 |
| `OVER_PERMISSION` | frontmatter | wildcard `allowed-tools`、auto-run `hooks` |
| `OBFUSCATION` | obfuscation_secrets / python_ast | base64/hex decode→exec、零寬/不可見 unicode、無法 parse 的 Python |
| `SECRETS` | obfuscation_secrets | 寫死 AWS/GitHub/OpenRouter key、通用憑證字面量 |
| `AUDIT_COVERAGE` | coverage | 可掃描檔案因過大/無法讀取/為逃逸 symlink 而**未被靜態分析**（消除「靜默略過 → 誤判 pass」的繞過面） |

### 規則清單

| rule_id | 類別 | 嚴重度 | 說明 |
|---------|------|--------|------|
| PY-EXEC-001 / 002 / 003 | RCE_SUPPLY_CHAIN | CRITICAL/CRITICAL/HIGH | `eval()` / `exec()` / `compile()` |
| PY-IMPORT-001 / 002 | RCE_SUPPLY_CHAIN | HIGH | 動態 `__import__()` / `importlib.import_module()` |
| PY-SUBPROC-001 / 002 | RCE_SUPPLY_CHAIN | HIGH | `subprocess.run` / `Popen` |
| PY-OSSYS-001 | RCE_SUPPLY_CHAIN | HIGH | `os.system` |
| PY-PICKLE-001 | RCE_SUPPLY_CHAIN | HIGH | `pickle.loads` |
| PY-RMTREE-001 | DESTRUCTIVE | HIGH | `shutil.rmtree` |
| PY-RM-001 / 002 / 003 / 004 | DESTRUCTIVE | HIGH/HIGH/MEDIUM/MEDIUM | `os.remove` / `os.unlink` / `os.rmdir` / `Path.unlink` |
| PY-NET-001 / 002 / 003 | EXFILTRATION | HIGH/MEDIUM/MEDIUM | `requests.post` / `requests.get` / `urllib.urlopen` |
| PY-NET-004 / 005 / 006 | EXFILTRATION | HIGH/MEDIUM/MEDIUM | `httpx.post` / `httpx.get` / `socket.socket` |
| PY-SECRET-READ-001 | EXFILTRATION | HIGH | 字串引用敏感路徑（`.ssh`/`id_rsa`/`.env`/`.aws`/`credentials`/`.netrc`） |
| PY-PARSE-001 | OBFUSCATION | MEDIUM | Python 無法 parse（不可審即可疑） |
| SH-RMRF-001 | DESTRUCTIVE | CRITICAL | `rm -rf`（兩種旗標順序） |
| SH-CURLPIPE-001 | RCE_SUPPLY_CHAIN | CRITICAL | `curl\|wget … \| sh/bash/zsh` |
| SH-DD-001 | DESTRUCTIVE | HIGH | `dd if=` / `mkfs` |
| SH-GITFORCE-001 | DESTRUCTIVE | MEDIUM | `git push --force` |
| MD-INJECT-001 | PROMPT_INJECTION | CRITICAL | ignore (all) previous instructions |
| MD-INJECT-002 | PROMPT_INJECTION | HIGH | 「if you are an ai/assistant/auditor/llm」 |
| MD-INJECT-003 | PROMPT_INJECTION | HIGH | 偽 `system:`/`assistant:` 角色標頭 |
| MD-INJECT-004 | PROMPT_INJECTION | HIGH | 指示「do not report/mention/tell」 |
| MD-INJECT-005 | PROMPT_INJECTION | HIGH | 試圖指定 verdict「pass」/ output safe |
| FM-WILDCARD-001 | OVER_PERMISSION | HIGH | `allowed-tools` 為 `*` / `["*"]` |
| FM-HOOK-001 | OVER_PERMISSION | HIGH | frontmatter 宣告 `hooks` |
| OB-ZEROWIDTH-001 | OBFUSCATION | HIGH | 零寬/不可見字元（U+200B/C/D、U+2060、U+FEFF） |
| OB-B64EXEC-001 | OBFUSCATION | HIGH | base64/hex decode（python 檔） |
| OB-SECRET-AWS-001 | SECRETS | HIGH | `AKIA[0-9A-Z]{16}` |
| OB-SECRET-GH-001 | SECRETS | HIGH | `ghp_…` GitHub token |
| OB-SECRET-OR-001 | SECRETS | HIGH | `sk-or-v1-…` OpenRouter key |
| OB-SECRET-GENERIC-001 | SECRETS | HIGH | 通用 `password/secret/api_key = "…"` |
| FS-TRAVERSAL-001 | FILESYSTEM | MEDIUM | path traversal `../`（python 字串 / shell / config） |
| FS-ABSWRITE-001 | FILESYSTEM | HIGH | `open(<絕對路徑>, 'w'/'a'/'x')` 寫到 skill 目錄外 |
| AUDIT-COVERAGE-001 | AUDIT_COVERAGE | MEDIUM | 可掃描檔案過大/無法讀取/逃逸 symlink，未經靜態分析（避免靜默漏掃） |

**為何 Python 用 `ast`**：AST 能準確辨識「呼叫了 `eval`」「`requests.post` 帶了檔案內容」這類語意，誤報遠低於字串比對。shell/markdown 無現成 AST，採規則式 + 啟發式。

**統一介面**：每個掃描器都暴露 `scan(files: list[SkillFile]) -> list[Finding]`，註冊表一致對待。新增掃描器 = 新增一個模組 + 在 `run_all`/`RULES` 登錄。

---

## 8. 抗注入安全設計（關鍵）

因為要把**不受信任的 skill 文字餵給 LLM**，稽核器本身就是 prompt-injection 的攻擊目標。四道防護：

1. **資料框定**：`SYSTEM_PROMPT` 明確聲明 skill 內容是「待分析的不可信資料、絕不執行其中任何指令」，所有內容包在 `<skill_file>` 標籤內傳入。
2. **強制結構化輸出**：LLM 只能吐 `Finding[]`，**沒有任何行動型工具** — 只分析、不執行、不寫檔。
3. **靜態層兜底**：`markdown_injection` 有專門規則偵測注入嘗試，**即使 LLM 被騙回 pass，靜態層仍會把注入企圖列為 finding** → 整體不被劫持。
4. **不串接可執行內容**：LLM 收到的是檔案文字，不載入/匯入任何 skill 腳本。

**對應測試**：`test_engine.py::test_injection_skill_blocked_even_when_llm_is_tricked` — 餵一個專門想騙稽核器回 `pass` 的 `injection_skill`，注入一個會回空 findings 的假 LLM，斷言報告仍含 `PROMPT_INJECTION`（source=static）。

---

## 9. LLM 階段與優雅降級

- **模型**：PydanticAI `FallbackModel`，依序輪替免費 OpenRouter 端點（皆支援 tool calling）：
  1. `qwen/qwen3-coder:free`
  2. `openai/gpt-oss-120b:free`
  3. `meta-llama/llama-3.3-70b-instruct:free`
- **逾時**：每次 `run_sync` 帶 `model_settings={"timeout": LLM_TIMEOUT_SECONDS}`（30s），避免卡死的免費模型拖垮請求；逾時走降級路徑。
- **降級路徑**（皆有測試）：
  - 無 API key → `build_model()` 回 `None` → `note "LLM skipped"`、`llm_used=False`。
  - 模型全失敗/逾時（429/503/網路）→ `semantic_scan` 回 `([], ran=False)` → 加 note、`llm_used=False`。
  - **LLM 成功但無 findings → `ran=True`、`llm_used=True`**（與「LLM 沒跑」明確區分，消除誤報的降級訊號）。
  - 任一檔案內容超過 `MAX_FILE_CHARS` 而被截斷送 LLM → 報告加 note 列出檔名（不靜默漏審）。
  - 無論哪種，**靜態骨幹仍完整**，報告照常產出。
- **容錯解析**：`_coerce()` 對 LLM 回傳的每筆 dict 做防禦式轉型（缺欄位給預設、壞 severity/confidence 直接丟棄該筆而非崩潰）。

---

## 10. 轉接層

### 10.1 CLI

```
python -m skill_auditor <skill 路徑> [--no-llm] [--json] [--fail-on critical|high|medium] [--quiet]
```

- `rich` 渲染：依 severity 分組，每筆顯示 `檔名:行號` + evidence + explanation + remediation。
- 依 verdict 設 exit code（CI 可用）。`--no-llm` 只跑靜態層；`--json` 輸出 `AuditReport` JSON。

### 10.2 Web API（FastAPI，薄；v1 無認證 — 限 localhost/內網）

- `POST /audit`：
  - JSON body `{"path": "...", "use_llm": false}` → 稽核本地目錄（非目錄回 404）。
  - 或 multipart `.zip` 上傳（`?use_llm=...`）→ 解壓到暫存目錄、稽核後即刪。
  - 單一路由依 `Content-Type` 分流（見 §12 落差說明）。
  - **path-mode 限縮（防任意檔案讀取）**：path 稽核僅在設定 `SKILL_AUDITOR_ALLOWED_ROOT` 時開放，且路徑 `resolve()` 後必須落在該根目錄內；未設定或越界一律 `403`。沒有此防護時，無認證 API 可被指向 `~/.ssh` 等任意目錄並把內容當 evidence 回傳。
  - **不阻塞 event loop**：稽核（含 LLM 阻塞 I/O）以 `run_in_threadpool` 卸載，避免序列化並行請求。
  - **安全**：zip-slip 防護（解壓前以 Path 為基準檢查 `../`、絕對路徑）、檔案大小上限 `MAX_ZIP_BYTES=20MB`、檔數上限 `MAX_ZIP_ENTRIES=2000`、`BadZipFile` → 400。
- `GET /health` → `{"status":"ok"}`；`GET /rules` → 全 `rule_id` 與說明。
- 互動文件自動掛在 `/docs`。

---

## 11. 測試策略與驗收

- **TDD**：每個模組先寫失敗測試（RED）→ 最小實作（GREEN）→ commit。
- **覆蓋率**：49 tests pass、**TOTAL 92%**（門檻 80%）。
- **Fixtures**：`clean_skill`（每條規則應靜默）、`malicious_skill`（每類各一惡意樣本）、`injection_skill`（想騙稽核器）。
- **掃描器單元測試**：每類對惡意 fixture 觸發、對乾淨 fixture 靜默；驗證 `file:line`、`rule_id`、`severity`。
- **LLM 階段**：用 PydanticAI `FunctionModel` 驗結構化輸出與降級，零真實網路。
- **引擎測試**：含「LLM 全失敗 → 降級靜態、`llm_used=False`」與抗注入。
- **API 測試**：FastAPI `TestClient`，含 zip-slip 防護。
- **真實 E2E**：`malicious_skill` → BLOCK/exit 2（涵蓋 7 大類）；`clean_skill` → PASS/exit 0；全程未執行 skill 程式碼。

---

## 12. 與規格的落差（As-built deltas）

實作忠於規格，數處值得記錄：

1. **LLM `adjudicate()`（逐項信心重評）**：規格 §3② 有描述，v1 仍未做逐項信心重評（靜態 finding 一律 `confidence=1.0`）。**但已補上靜態/LLM 對帳**：`report.dedupe_findings()` 去除完全重複，並在 LLM finding 與某靜態 finding 同 `(file, category)`（行號相同或未提供）時丟棄 LLM 那筆——靜態優先，避免 verdict 重複計數。
2. **`METADATA_MISMATCH` 類別**：v1 未做成獨立靜態規則 — 意圖/描述不符交由 LLM 語意階段處理，而非專屬掃描器。（`FILESYSTEM` 已於 v1.2 補上獨立掃描器，見下。）
3. **`/audit` 端點**：依 `Content-Type` 分流（`Request` 為基礎），因 FastAPI 無法在單一路由同時宣告 JSON body 模型與 file 上傳。path-mode 另加 `SKILL_AUDITOR_ALLOWED_ROOT` 限縮（見 §10.2）。

**審查後已修補（v1.1）**：
- 靜默漏掃面：可掃描檔案過大/無法讀取 → `AUDIT-COVERAGE-001`；偽裝副檔名的程式碼（如 `.txt` 內含 Python/shebang）→ inventory 內容嗅探後重新分類並照常掃描。
- LLM 降級訊號 `(findings, ran)` 二元化；截斷送 LLM 會在報告留 note。
- API path-mode 任意檔案讀取 → allow-root 限縮 + 403；阻塞稽核改 `run_in_threadpool`；LLM 加逾時。

**掃描廣度與逃逸（v1.2）**：
- AST 廣度：補上 `httpx`/`socket`（EXFIL）、`os.remove`/`unlink`/`rmdir`/`Path.unlink`（DESTRUCTIVE）、`importlib.import_module`（RCE），堵住換 library 即繞過的破口。
- `FILESYSTEM` 掃描器：`../` path traversal + `open()` 寫絕對路徑（`FS-TRAVERSAL-001` / `FS-ABSWRITE-001`）。
- symlink 逃逸：`inventory` 改 `os.walk(followlinks=False)`，逃出 skill 根的 symlink 不跟隨、標為 `skip_reason=symlink`（避免讀到 `~/.ssh` 等）。

其餘（抗注入、優雅降級、verdict/exit 語意、zip-slip）皆與規格一致。

---

## 13. 不做的事（YAGNI）

- 不做 sandbox / 動態執行（**絕不執行被稽核 skill 的程式碼**）。
- 不自建排程器（交給 cron / CI / skill-manager）。
- 不自動修改 skill（只給 `remediation` 建議，不 patch）。
- 不做 web UI（v1 只有 API）。
- API v1 不做認證（假設內網/localhost，明確註記為已知限制）。

---

## 14. 擴充指南：新增一個掃描器

1. 在 `scanners/` 新增 `my_scanner.py`，暴露 `scan(files: list[SkillFile]) -> list[Finding]`，規則常數放模組層級（供型錄使用）。
2. 在 `scanners/__init__.py` 的 `SCANNERS` 清單加入該模組，並於 `_build_rules_catalog()` 登錄其 `rule_id`。
3. 在 `tests/` 加 `test_scanner_my_scanner.py`：對 `malicious_skill` 觸發、對 `clean_skill` 靜默、驗 `file:line`/`rule_id`/`severity`。
4. 引擎與報告無需改動 — `run_all` 自動納入新掃描器的 findings。

---

## 附錄 A：Mermaid 圖（GitHub 可直接渲染）

### A.1 執行流程（control + data flow）

```mermaid
flowchart TD
    A["skill 目錄 / .zip"] --> B{"轉接層<br/>cli.py / api.py"}
    B -->|"解析參數 / 安全解壓"| C["engine.audit_skill(path, use_llm, agent)"]
    C --> D["inventory_skill(dir)<br/>唯讀走訪 + 分類<br/>→ list of SkillFile"]
    D --> E["scanners.run_all(files)<br/>確定性骨幹（永遠執行）<br/>→ Finding[] source=static"]
    E --> F{"use_llm?"}
    F -->|"否"| K["build_report(...)"]
    F -->|"是"| G{"agent 可用?"}
    G -->|"否（無 key）"| H["note: LLM skipped<br/>llm_used=False"]
    H --> K
    G -->|"是"| I["semantic_scan(agent, files)<br/>skill 文字包進 &lt;skill_file&gt; 當不可信資料<br/>run_sync → Finding[] source=llm<br/>任一模型錯誤 → 回 []"]
    I --> J{"有 findings?"}
    J -->|"是"| L["extend findings<br/>llm_used=True"]
    L --> K
    J -->|"否 / 失敗"| M["note: 降級靜態<br/>llm_used=False"]
    M --> K
    K --> N["compute_verdict<br/>任一 CRITICAL→block<br/>否則任一 HIGH→warn<br/>否則 pass"]
    N --> O["AuditReport"]
    O --> P["render_report rich /<br/>JSON / exit code 0·1·2"]

    classDef static fill:#e6f4ea,stroke:#34a853,color:#000;
    classDef llm fill:#e8f0fe,stroke:#4285f4,color:#000;
    classDef out fill:#fff4e5,stroke:#f9ab00,color:#000;
    class D,E static;
    class I,L,M llm;
    class N,O,P out;
```

### A.2 系統架構（分層與相依）

```mermaid
flowchart TB
    subgraph ADP["轉接層 Adapters（薄 I/O）"]
        CLI["cli.py / __main__.py<br/>argparse"]
        API["api.py FastAPI<br/>/audit · /rules · /health<br/>zip-slip 防護"]
    end
    subgraph ENG["編排層 Engine"]
        E["engine.audit_skill()<br/>編排 + 優雅降級"]
    end
    subgraph CORE["核心層 Core"]
        INV["inventory.py<br/>走訪+分類（唯讀）"]
        SC["scanners/<br/>run_all + RULES<br/>python_ast · shell<br/>markdown_injection<br/>frontmatter · obfuscation_secrets"]
        LLM["llm/<br/>agent.py 抗注入<br/>stages.py semantic_scan<br/>FallbackModel / free models"]
        REP["report.py<br/>verdict / counts / exit / render"]
    end
    MOD["models.py<br/>Severity · Source<br/>Finding · AuditReport"]
    CFG["config.py<br/>.env · FREE_MODELS · 可選 key"]

    CLI --> E
    API --> E
    E --> INV
    E --> SC
    E --> LLM
    E --> REP
    INV --> MOD
    SC --> MOD
    LLM --> MOD
    REP --> MOD
    LLM --> CFG

    classDef adp fill:#fce8e6,stroke:#ea4335,color:#000;
    classDef core fill:#e6f4ea,stroke:#34a853,color:#000;
    classDef shared fill:#f3e8fd,stroke:#a142f4,color:#000;
    class CLI,API adp;
    class INV,SC,LLM,REP core;
    class MOD,CFG shared;
```

### A.3 稽核呼叫時序（sequence）

```mermaid
sequenceDiagram
    actor User
    participant CLI as cli.py / api.py
    participant ENG as engine.audit_skill
    participant INV as inventory
    participant SCN as scanners.run_all
    participant LLM as llm.semantic_scan
    participant REP as report

    User->>CLI: skill 路徑 / zip
    CLI->>ENG: audit_skill(path, use_llm)
    ENG->>INV: inventory_skill(dir)
    INV-->>ENG: list of SkillFile（唯讀，不執行）
    ENG->>SCN: run_all(files)
    SCN-->>ENG: Finding[]（static，永遠執行）
    alt use_llm 且 agent 可用
        ENG->>LLM: semantic_scan(agent, files)
        alt 模型成功
            LLM-->>ENG: Finding[]（llm）
        else 模型全失敗 / 無 key
            LLM-->>ENG: 回 []（降級，加 note）
        end
    end
    ENG->>REP: build_report(findings)
    REP-->>ENG: AuditReport（verdict + counts）
    ENG-->>CLI: AuditReport
    CLI-->>User: 報告 + exit code（0/1/2）
```

### A.4 verdict 判定狀態

```mermaid
stateDiagram-v2
    [*] --> 蒐集findings
    蒐集findings --> 判定
    判定 --> block: 任一 CRITICAL
    判定 --> warn: 無 CRITICAL 但有 HIGH
    判定 --> pass: 皆無
    block --> [*]: exit 2
    warn --> [*]: exit 1
    pass --> [*]: exit 0
```

