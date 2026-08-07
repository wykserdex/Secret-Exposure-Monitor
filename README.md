# Secret Exposure Monitor

Detect, classify, and remediate exposed secrets in Git repositories with Campaign Graph integration.

## Features

- **Multi-provider support**: GitHub, GitLab, Gitea, and local repositories
- **Secure scanning**: HMAC fingerprinting, no raw secrets stored
- **Gitleaks integration**: Industry-standard secret detection engine
- **Remediation workflows**: Revoke, rotate, and clean up exposed secrets
- **Campaign Graph ready**: Graph-compatible events for future correlation
- **Security-first**: Isolated scanner, redacted logs, tenant isolation

## Installation

```bash
pip install -e .
```

## CLI Usage

```bash
sem --help
```

**Важно:** `sem scan` и `sem remediate` пока заглушки. `scan` печатает
"Scan initiated (mock)" и не запускает `GitleaksEngine`; `remediate` не
выполняет ни одного шага remediation. Реальный сканер (`GitleaksEngine`,
покрыт тестами) существует и работает как отдельный класс, но CLI его
пока не вызывает — это следующий шаг, не то, что можно использовать
сегодня из командной строки.

```bash
# Печатает "Scanning ./my-repo for tenant ..." и заглушку JSON — не сканирует
sem scan ./my-repo --tenant-id <uuid> --repository-id <uuid> --json
```

## Архитектура

Реальная структура пакета:

```
secret_exposure_monitor/
├── cli.py                    # argparse CLI (scan/remediate — заглушки)
├── domain/
│   ├── finding.py            # SecretFinding, FindingStatus, ConfidenceLevel
│   ├── remediation.py        # RemediationPlaybook, RemediationWorkflow
│   ├── repository.py         # Repository, RepoProvider
│   └── secret.py             # HMAC fingerprint, redaction, SecretType (не используется)
├── scanning/
│   ├── pipeline.py           # ScannerEngine (abstract), ScanResult
│   └── engines/gitleaks.py   # GitleaksEngine — реально вызывает gitleaks через subprocess
└── correlation_contracts/
    └── events.py             # GraphRelation, SecretExposureDetected — для будущего Campaign Graph
```

Того, что перечислено в README более ранних версий этого проекта —
`ingress/`, `providers/`, `classification/`, `remediation/` (как пакет),
`policy/`, `storage/`, `broker/` — в этой версии физически нет. Это
следующие шаги, а не то, что уже реализовано.

## Security Model

### Never Store
- Raw secret values
- Full diff content
- Environment dumps

### Always Protect
- HMAC-SHA256 fingerprints with tenant-specific keys
- Redacted previews (e.g., `ghp_****b82a`)
- Scanner runs in isolated container (no network, read-only root)

### Webhook Security
- HMAC signature verification
- Replay protection with delivery ID
- Timestamp window validation
- Rate limiting

## Event Schema

```python
class SecretExposureDetected(BaseModel):
    event_id: UUID
    tenant_id: UUID
    finding_id: UUID
    repository_id: UUID
    commit_sha: str
    secret_fingerprint: str  # HMAC, not raw value
    secret_type: str
    severity: str
    confidence: float
    graph_hints: list[str]  # For Campaign Graph correlation
```

## Remediation Playbook

1. **Revoke** the exposed secret (block at provider)
2. **Rotate** with new credentials
3. **Update** CI/CD and Secret Manager
4. **Delete** from current file
5. **Clean history** (manual approval required)
6. **Notify** affected teams
7. **Resolve** incident after verification

## Configuration

**Пока не реализовано.** Ни одна из переменных окружения ниже сейчас не
читается никаким кодом в репозитории — это описание того, что нужно будет
для реального деплоя (когда появится storage/broker/providers), а не
рабочий конфиг сегодня.

```bash
export SEM_TENANT_KEY="<hmac-key-from-vault>"
export SEM_DATABASE_URL="postgresql+asyncpg://..."
export SEM_KAFKA_BROKERS="kafka:9092"
export SEM_GITLEAKS_PATH="/usr/local/bin/gitleaks"
```

## Найденные и исправленные баги (для истории)

1. **`GitleaksEngine.scan_diff()` игнорировал свой собственный аргумент
   `diff` целиком.** Записывал diff-текст во временный файл, который потом
   ни разу не упоминался в реальной команде — subprocess вызывал
   `gitleaks detect --source repo_path --no-git`, то есть сканировал
   `repo_path` как директорию, а не переданный diff. Функция называлась
   "scan diff", а по факту сканировала что угодно, что лежало в
   `repo_path`. Исправлено на `--pipe` с передачей diff через stdin — это
   задокументированный способ сканирования произвольного текста в Gitleaks
   (`cat file | gitleaks detect --pipe`). `scan_file()` больше не
   делегирует в `scan_diff()` (раньше это работало только потому, что
   `scan_diff` игнорировала свой diff-аргумент; после фикса делегирование
   сломало бы `scan_file`) — теперь у него отдельная реализация через
   `--source` на временную директорию.
2. **`_normalize_findings()` сохранял реальный текст совпадения секрета**
   под ключом `raw_match` (Gitleaks `Match` — это буквально подстрока с
   секретом). `ScanResult.findings` типизирован как `list[dict[str, Any]]`
   без какой-либо схемы, и нигде в коде не было конвертера, который бы
   зафингерпринтил/отредактировал это значение — то есть сырой секрет
   осел бы без защиты в первом же месте, которое реально стало бы
   потреблять `ScanResult` (логи, API-ответ и т.п.). Убрано полностью,
   вместо него — только `match_length` (для триажа, не сама подстрока).
3. **`RemediationPlaybook.provider` был обязательным `str`.** Секреты без
   определённого провайдера (например `generic_high_entropy_string`) не
   смогли бы создать плейбук — `ValidationError` при любой попытке. Пока
   ничто в этой версии репозитория не создаёт `RemediationPlaybook`
   реально, так что баг не проявлялся, но это ровно та же мина, что уже
   ловилась в более ранней версии этого же проекта (там она реально ломала
   `RemediationOrchestrator()` при каждом вызове). Исправлено проактивно:
   `Optional[str] = None`.
4. **`scan_history()` использовал `--from-commit`** — флага с таким
   именем нет в документации Gitleaks. Заменено на `--log-opts
   "{from_commit}..HEAD"` — подтверждённый флаг для ограничения диапазона
   `git log`.
5. README перечислял `ingress/`, `providers/`, `classification/`,
   `remediation/` (как пакет), `policy/`, `storage/`, `broker/` — ни один
   из этих модулей физически не существует в этой версии. CLI-примеры
   выглядели как рабочие команды, хотя `sem scan`/`sem remediate` —
   заглушки. Секция `Configuration` описывала переменные окружения,
   которые не читает ни одна строка кода. Всё переписано честно.
6. Лицензия — MIT → AGPL-3.0, для консистентности с остальными
   репозиториями (Leak-Intelligence, wykse, UntilPhish-Go).

Добавлено 7 новых тестов (`test_gitleaks_regressions.py` +
`TestRemediationPlaybook`), которые ловят баги 1–3 конкретно — mock на
`subprocess.run` проверяет реальные аргументы вызова, а не только то, что
функция не падает. 60 тестов проходят (было 53).

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy secret_exposure_monitor

# Linting
ruff check secret_exposure_monitor
black --check secret_exposure_monitor
```

## License

AGPL-3.0 — см. [LICENSE](./LICENSE). Использование как сервиса (в т.ч. через
сеть) обязывает открыть исходники любых изменений под той же лицензией.
