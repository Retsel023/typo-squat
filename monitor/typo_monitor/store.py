"""Transactional observation history with conservative DNS change detection.

Discovery is an accumulating inventory, not evidence that a host disappeared.
Only explicit NXDOMAIN/no-answer checks count toward a confirmed disappearance.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
import sqlite3
from urllib.parse import urlsplit
from uuid import uuid4

from .domains import normalize_domain, normalize_records


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class Store:
    _RUN_SUMMARY_COLUMNS = ("id,project_id,status,started_at,finished_at,is_baseline,"
                            "'[]' AS events_json,counts_json,source_status_json,error,dns_workers,discovery_mode,report_deleted,"
                            "proxy_status_json,dns_route_key,capture_filter_json,capture_policy_json")
    _STATE_QUERY = """SELECT d.*,
        EXISTS(SELECT 1 FROM inventory i WHERE i.project_id=d.project_id
            AND i.domain=d.domain AND i.kind='seed') AS is_seed,
        e.parking_status,e.parking_provider,e.parking_evidence_json,e.parking_checked_at
        FROM domain_states d LEFT JOIN domain_enrichment e
            ON e.project_id=d.project_id AND e.domain=d.domain"""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "monitor.sqlite3"
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY, value_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    roots_json TEXT NOT NULL, created_at TEXT NOT NULL,
                    baseline_run_id TEXT, comparison_scope_json TEXT,
                    schedule_interval_hours REAL DEFAULT NULL,
                    schedule_next_run_at TEXT, dns_workers INTEGER,
                    discovery_mode TEXT NOT NULL DEFAULT 'enumerate'
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
                    is_baseline INTEGER NOT NULL DEFAULT 0,
                    events_json TEXT NOT NULL DEFAULT '[]',
                    counts_json TEXT NOT NULL DEFAULT '{}',
                    source_status_json TEXT NOT NULL DEFAULT '{}', error TEXT,
                    dns_workers INTEGER, discovery_mode TEXT,
                    report_deleted INTEGER NOT NULL DEFAULT 0
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_running_scan
                    ON runs(project_id) WHERE status = 'running';
                CREATE INDEX IF NOT EXISTS project_runs ON runs(project_id, started_at DESC);
                CREATE TABLE IF NOT EXISTS inventory (
                    project_id TEXT NOT NULL REFERENCES projects(id), domain TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('seed', 'candidate')),
                    PRIMARY KEY(project_id, domain, kind)
                );
                CREATE TABLE IF NOT EXISTS domain_states (
                    project_id TEXT NOT NULL REFERENCES projects(id), domain TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'unknown',
                    records_json TEXT NOT NULL DEFAULT '[]',
                    first_seen TEXT, last_seen TEXT, last_checked TEXT, last_error TEXT,
                    missing_count INTEGER NOT NULL DEFAULT 0,
                    latest_observation TEXT NOT NULL DEFAULT 'unknown',
                    PRIMARY KEY(project_id, domain)
                );
                CREATE TABLE IF NOT EXISTS observations (
                    run_id TEXT NOT NULL REFERENCES runs(id), domain TEXT NOT NULL,
                    status TEXT NOT NULL, records_json TEXT NOT NULL, error TEXT,
                    PRIMARY KEY(run_id, domain)
                );
                CREATE INDEX IF NOT EXISTS states_by_status
                    ON domain_states(project_id,status,domain);
                CREATE TABLE IF NOT EXISTS candidate_sources (
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    domain TEXT NOT NULL, seed TEXT NOT NULL,
                    PRIMARY KEY(project_id,domain,seed)
                );
                CREATE INDEX IF NOT EXISTS sources_by_seed
                    ON candidate_sources(project_id,seed,domain);
                CREATE TABLE IF NOT EXISTS domain_enrichment (
                    project_id TEXT NOT NULL REFERENCES projects(id), domain TEXT NOT NULL,
                    parking_status TEXT NOT NULL DEFAULT 'unknown', parking_provider TEXT,
                    parking_evidence_json TEXT NOT NULL DEFAULT '[]', parking_checked_at TEXT,
                    PRIMARY KEY(project_id,domain)
                );
                CREATE TABLE IF NOT EXISTS captures (
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    project_id TEXT NOT NULL REFERENCES projects(id), domain TEXT NOT NULL,
                    scheme TEXT NOT NULL CHECK(scheme IN ('http','https')),
                    status TEXT NOT NULL CHECK(status IN ('captured','failed','unavailable','skipped')),
                    relative_path TEXT, url TEXT NOT NULL, title TEXT, http_status INTEGER,
                    error TEXT, captured_at TEXT NOT NULL,
                    visual_json TEXT NOT NULL DEFAULT '{}',
                    analysis_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY(run_id,domain,scheme)
                );
                CREATE INDEX IF NOT EXISTS captures_by_scheme
                    ON captures(project_id,domain,scheme,captured_at DESC);
                CREATE INDEX IF NOT EXISTS captures_by_domain
                    ON captures(project_id,domain,captured_at DESC);
                CREATE TABLE IF NOT EXISTS generation_markers (
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    signature TEXT NOT NULL, seed TEXT NOT NULL,
                    run_id TEXT NOT NULL REFERENCES runs(id), generated_at TEXT NOT NULL,
                    PRIMARY KEY(project_id,signature,seed)
                );
                CREATE TABLE IF NOT EXISTS artifact_cleanup (
                    run_id TEXT PRIMARY KEY
                );
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    discovery_mode TEXT NOT NULL CHECK(discovery_mode IN ('enumerate','cached')),
                    interval_hours REAL NOT NULL, next_run_at TEXT,
                    PRIMARY KEY(project_id,discovery_mode)
                );
            """)
        # Existing development databases predate resolver-scope persistence.
        # Serialize the inspection and ALTER to make concurrent startup safe.
        with self._connection(write=True) as db:
            columns = {row["name"] for row in db.execute("PRAGMA table_info(projects)")}
            if "comparison_scope_json" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN comparison_scope_json TEXT")
            if "schedule_interval_hours" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN schedule_interval_hours REAL DEFAULT NULL")
            if "schedule_next_run_at" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN schedule_next_run_at TEXT")
            if "dns_workers" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN dns_workers INTEGER")
            if "discovery_mode" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN discovery_mode TEXT NOT NULL DEFAULT 'enumerate'")
            if "proxy_settings_json" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN proxy_settings_json TEXT NOT NULL DEFAULT '{}'")
            if "dns_route_key" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN dns_route_key TEXT NOT NULL DEFAULT 'direct'")
            if "capture_filter_json" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN capture_filter_json TEXT NOT NULL DEFAULT '{}'")
            if "capture_policy_json" not in columns:
                db.execute("ALTER TABLE projects ADD COLUMN capture_policy_json TEXT NOT NULL DEFAULT '{}'")
            run_columns = {row["name"] for row in db.execute("PRAGMA table_info(runs)")}
            if "dns_workers" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN dns_workers INTEGER")
            if "discovery_mode" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN discovery_mode TEXT")
            if "report_deleted" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN report_deleted INTEGER NOT NULL DEFAULT 0")
            if "proxy_status_json" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN proxy_status_json TEXT NOT NULL DEFAULT '{}'")
            if "dns_route_key" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN dns_route_key TEXT NOT NULL DEFAULT 'direct'")
            if "capture_filter_json" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN capture_filter_json TEXT NOT NULL DEFAULT '{}'")
            if "capture_policy_json" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN capture_policy_json TEXT NOT NULL DEFAULT '{}'")
            schedule_columns = {row["name"] for row in db.execute("PRAGMA table_info(scan_schedules)")}
            if "capture_mode" not in schedule_columns:
                db.execute("ALTER TABLE scan_schedules ADD COLUMN capture_mode TEXT NOT NULL DEFAULT 'changes'")
            db.execute("""CREATE INDEX IF NOT EXISTS project_schedule_due ON projects(schedule_next_run_at)
                WHERE schedule_interval_hours>0""")
            capture_columns = {row["name"] for row in db.execute("PRAGMA table_info(captures)")}
            for column in ("visual_json", "analysis_json"):
                if column not in capture_columns:
                    db.execute(f"ALTER TABLE captures ADD COLUMN {column} TEXT NOT NULL DEFAULT '{{}}'")
            if "preflight_json" not in capture_columns:
                db.execute("ALTER TABLE captures ADD COLUMN preflight_json TEXT NOT NULL DEFAULT '{}'")

    @contextmanager
    def _connection(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _project(db, row):
        if row is None:
            return None
        result = dict(row)
        # Private proxy URLs may contain credentials; no normal project reader,
        # template, API response or export is allowed to receive those URLs.
        result.pop("proxy_settings_json", None)
        result.pop("dns_route_key", None)
        result["capture_filter"] = json.loads(result.pop("capture_filter_json", "{}"))
        from .capture_changes import normalize_policy
        result["capture_policy"] = normalize_policy(**json.loads(result.pop("capture_policy_json", "{}")))
        result["roots"] = json.loads(result.pop("roots_json"))
        scope_json = result.pop("comparison_scope_json")
        result["comparison_scope"] = json.loads(scope_json) if scope_json is not None else None
        result.pop("baseline_run_id", None)
        latest = db.execute(
            f"SELECT {Store._RUN_SUMMARY_COLUMNS} FROM runs WHERE project_id=? ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (result["id"],),
        ).fetchone()
        result["last_run"] = Store._run(latest)
        result["schedules"] = {row["discovery_mode"]: dict(row) for row in db.execute(
            "SELECT discovery_mode,interval_hours,next_run_at,capture_mode FROM scan_schedules WHERE project_id=?",
            (result["id"],))}
        return result

    @staticmethod
    def _run(row):
        if row is None:
            return None
        result = dict(row)
        for key in ("events", "counts", "source_status"):
            result[key] = json.loads(result.pop(key + "_json"))
        result["is_baseline"] = bool(result["is_baseline"])
        result["report_deleted"] = bool(result.get("report_deleted", False))
        result["proxy_status"] = json.loads(result.pop("proxy_status_json", "{}"))
        result["capture_filter"] = json.loads(result.pop("capture_filter_json", "{}"))
        result["capture_policy"] = json.loads(result.pop("capture_policy_json", "{}"))
        result.pop("dns_route_key", None)
        return result

    @staticmethod
    def _state(row):
        result = dict(row)
        result.pop("project_id", None)
        result["records"] = json.loads(result.pop("records_json"))
        result["is_seed"] = bool(result.pop("is_seed", False))
        result["sources"] = []
        result["screenshots"] = []
        result["parking"] = {
            "status": result.pop("parking_status", None) or "unknown",
            "provider": result.pop("parking_provider", None),
            "evidence": json.loads(result.pop("parking_evidence_json", None) or "[]"),
            "checked_at": result.pop("parking_checked_at", None),
        }
        return result

    @staticmethod
    def _public_states(db, project_id, rows):
        items = [Store._state(row) for row in rows]
        by_domain = {item["domain"]: item for item in items}
        domains = list(by_domain)
        # Stay below older SQLite parameter limits without a query per domain.
        for offset in range(0, len(domains), 800):
            batch = domains[offset:offset + 800]
            placeholders = ",".join("?" for _ in batch)
            for row in db.execute(
                f"SELECT domain,seed FROM candidate_sources WHERE project_id=? AND domain IN ({placeholders}) ORDER BY domain,seed",
                [project_id, *batch],
            ):
                by_domain[row["domain"]]["sources"].append(row["seed"])
            # Only latest attempts and latest successful images reach the UI;
            # older artifacts remain available through capture history.
            latest, successful = {}, {}
            for row in db.execute(f"""SELECT * FROM (
                SELECT c.*,
                    ROW_NUMBER() OVER(PARTITION BY domain,scheme ORDER BY captured_at DESC,rowid DESC) AS attempt_rank,
                    ROW_NUMBER() OVER(PARTITION BY domain,scheme,status ORDER BY captured_at DESC,rowid DESC) AS status_rank
                FROM captures c WHERE project_id=? AND domain IN ({placeholders})
                ) WHERE attempt_rank=1 OR (status='captured' AND status_rank=1)""", [project_id, *batch]):
                key = (row["domain"], row["scheme"])
                capture = Store._capture(row)
                if row["attempt_rank"] == 1:
                    latest[key] = capture
                if row["status"] == "captured" and row["status_rank"] == 1:
                    successful[key] = capture
            for key in sorted(latest):
                capture = latest[key]
                if capture["status"] != "captured" and key in successful:
                    capture["previous_capture"] = successful[key]
                by_domain[key[0]]["screenshots"].append(capture)
        return items

    @staticmethod
    def _capture(row):
        if row is None:
            return None
        capture = dict(row)
        capture.pop("attempt_rank", None)
        capture.pop("status_rank", None)
        capture["visual"] = json.loads(capture.pop("visual_json", "{}"))
        capture["analysis"] = json.loads(capture.pop("analysis_json", "{}"))
        capture["preflight"] = json.loads(capture.pop("preflight_json", "{}"))
        return capture

    @staticmethod
    def _normalize_screenshots(screenshots):
        if screenshots is None:
            return {}
        if not isinstance(screenshots, Mapping):
            raise ValueError("Screenshots must map candidate domains to capture attempts.")
        normalized = {}
        for domain, attempts in screenshots.items():
            domain = normalize_domain(domain)
            if domain in normalized or not isinstance(attempts, (list, tuple)):
                raise ValueError("Screenshots require one list of attempts per domain.")
            normalized[domain] = []
            schemes = set()
            for attempt in attempts:
                if not isinstance(attempt, Mapping):
                    raise ValueError("Invalid screenshot attempt.")
                scheme, status = attempt.get("scheme"), attempt.get("status")
                if scheme not in ("http", "https") or scheme in schemes:
                    raise ValueError("Screenshot schemes must be unique HTTP or HTTPS targets.")
                if status not in ("captured", "failed", "unavailable", "skipped"):
                    raise ValueError("Invalid screenshot status.")
                schemes.add(scheme)
                relative_path = attempt.get("relative_path")
                if status == "captured":
                    if (not isinstance(relative_path, str) or not relative_path
                            or "\\" in relative_path or any(ord(c) < 32 for c in relative_path)
                            or PurePosixPath(relative_path).is_absolute()
                            or PureWindowsPath(relative_path).drive
                            or ".." in PurePosixPath(relative_path).parts
                            or PurePosixPath(relative_path).suffix.lower() not in {".png", ".jpg", ".jpeg"}):
                        raise ValueError("Screenshot paths must be relative PNG or JPEG files within the run directory.")
                    relative_path = PurePosixPath(relative_path).as_posix()
                elif relative_path is not None:
                    raise ValueError("Unsuccessful screenshot attempts cannot claim an image path.")
                url = attempt.get("url", f"{scheme}://{domain}")
                try:
                    parsed = urlsplit(url)
                    valid_url = (parsed.scheme == scheme and normalize_domain(parsed.hostname or "") == domain
                                 and parsed.username is None and parsed.password is None)
                    parsed.port  # Reject malformed ports even when a hostname parsed.
                except (TypeError, ValueError, AttributeError):
                    valid_url = False
                if not isinstance(url, str) or not valid_url:
                    raise ValueError("Screenshot URL must match the candidate domain and scheme.")
                title, error, http_status = attempt.get("title"), attempt.get("error"), attempt.get("http_status")
                if ((title is not None and not isinstance(title, str))
                        or (error is not None and not isinstance(error, str))
                        or (http_status is not None and (not isinstance(http_status, int) or isinstance(http_status, bool)))):
                    raise ValueError("Invalid screenshot title, HTTP status, or error.")
                timestamp = attempt.get("captured_at", _now())
                visual = attempt.get("visual", {})
                if not isinstance(visual, dict) or len(_json(visual)) > 16384:
                    raise ValueError("Invalid screenshot comparison metadata.")
                preflight = attempt.get("preflight", {})
                if not isinstance(preflight, dict) or len(_json(preflight)) > 65536:
                    raise ValueError("Invalid website preflight metadata.")
                try:
                    captured_at = datetime.fromisoformat(timestamp)
                    if captured_at.tzinfo is None or captured_at.utcoffset() != timedelta(0):
                        raise ValueError("Screenshot timestamps must be UTC.")
                except (TypeError, ValueError) as exc:
                    raise ValueError("Screenshot timestamps must be UTC ISO dates.") from exc
                normalized[domain].append({"scheme": scheme, "status": status, "relative_path": relative_path,
                    "url": url, "title": title, "http_status": http_status, "error": error,
                    "captured_at": captured_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
                    "visual": visual, "preflight": preflight})
        return normalized

    @staticmethod
    def _require_project(db, project_id):
        row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            raise ValueError("Project not found.")
        return row

    @staticmethod
    def _require_running(db, run_id):
        row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("Run not found.")
        if row["status"] != "running":
            raise ValueError("This run has already finished.")
        return row

    def create_project(self, name, roots):
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 128:
            raise ValueError("Project name must contain 1–128 characters.")
        if isinstance(roots, str):
            raise ValueError("Roots must be a list of domain names.")
        roots = sorted({normalize_domain(domain) for domain in roots})
        if not roots:
            raise ValueError("At least one root domain is required.")
        project_id = str(uuid4())
        with self._connection(write=True) as db:
            db.execute(
                "INSERT INTO projects(id,name,roots_json,created_at) VALUES(?,?,?,?)",
                (project_id, name.strip(), _json(roots), _now()),
            )
            db.executemany("INSERT INTO inventory VALUES(?,?, 'seed')", [(project_id, d) for d in roots])
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def list_projects(self):
        with self._connection() as db:
            return [self._project(db, row) for row in db.execute("SELECT * FROM projects ORDER BY created_at, id").fetchall()]

    def get_project(self, project_id):
        with self._connection() as db:
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def rename_project(self, project_id, name):
        if (not isinstance(name, str) or not name.strip() or len(name.strip()) > 120
                or any(ord(c) < 32 or ord(c) == 127 for c in name)):
            raise ValueError("Project name must contain 1–120 printable characters.")
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            db.execute("UPDATE projects SET name=? WHERE id=?", (name.strip(), project_id))

    def proxy_settings(self, project_id):
        """Private worker/settings access. Never put this return value in logs."""
        with self._connection() as db:
            project = self._require_project(db, project_id)
            from .proxy import resolve_settings
            return resolve_settings(json.loads(project["proxy_settings_json"]))

    def set_proxy_settings(self, project_id, changes):
        from .proxy import STAGES, TOR_STAGES, validate_url, public_settings, tor_proxy_url
        if set(changes) != set(STAGES):
            raise ValueError("Provide settings for all three proxy stages.")
        with self._connection(write=True) as db:
            project = self._require_project(db, project_id)
            settings = json.loads(project["proxy_settings_json"])
            for stage in STAGES:
                change = changes[stage]
                old = settings.get(stage, {})
                source = change.get("source", old.get("source", "custom"))
                if not isinstance(source, str) or source not in {"custom", "tor"} or source == "tor" and stage not in TOR_STAGES:
                    raise ValueError("Choose a custom proxy, or Tor for discovery/website capture. Tor does not support UDP DNS.")
                custom_url = (change.get("url", "").strip() or old.get("custom_url",
                              old.get("url", "") if old.get("source", "custom") == "custom" else ""))
                if custom_url:
                    validate_url(custom_url)
                enabled = bool(change.get("enabled")) and not change.get("clear")
                if change.get("clear"):
                    source, custom_url = "custom", ""
                value = tor_proxy_url() if source == "tor" else custom_url
                if value:
                    validate_url(value)
                if enabled and not value:
                    raise ValueError(f"Configure a SOCKS5 proxy before enabling {stage}.")
                settings[stage] = {"enabled": enabled, "url": value, "source": source, "custom_url": custom_url}
            db.execute("UPDATE projects SET proxy_settings_json=? WHERE id=?", (_json(settings), project_id))
            return public_settings(settings)

    @staticmethod
    def _global_capture_filter(db):
        row = db.execute("SELECT value_json FROM app_settings WHERE key='capture_filter'").fetchone()
        return json.loads(row["value_json"]) if row else {"enabled": False, "rules": []}

    def global_capture_filter(self):
        with self._connection() as db:
            return self._global_capture_filter(db)

    def set_global_capture_filter(self, *, enabled, rules):
        from .title_filter import normalize_policy
        policy = normalize_policy(enabled, rules)
        with self._connection(write=True) as db:
            db.execute("""INSERT INTO app_settings(key,value_json) VALUES('capture_filter',?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json""", (_json(policy),))
        return policy

    def set_capture_filter(self, project_id, *, enabled, rules):
        from .title_filter import normalize_policy
        policy = normalize_policy(enabled, rules)
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            db.execute("UPDATE projects SET capture_filter_json=? WHERE id=?", (_json(policy), project_id))
        return policy

    def set_capture_policy(self, project_id, *, mode, refresh_days, comparison="text", **performance):
        from .capture_changes import normalize_policy
        policy = normalize_policy(mode, refresh_days, comparison, **performance)
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            db.execute("UPDATE projects SET capture_policy_json=? WHERE id=?", (_json(policy), project_id))
        return policy

    @staticmethod
    def _require_idle(db, project_id):
        if db.execute("SELECT 1 FROM runs WHERE project_id=? AND status='running'", (project_id,)).fetchone():
            raise RuntimeError("Stop this project's scan and wait for its worker to finish before deleting.")

    def delete_report(self, run_id):
        """Remove report content, retaining only scan bookkeeping and cache references.

        Inventory and accepted DNS state are independent of report retention.
        Keeping the run identity prevents history pruning from resetting the
        baseline, generation cache or automatic schedule's last attempt time.
        """
        with self._connection(write=True) as db:
            run = db.execute("SELECT * FROM runs WHERE id=? AND report_deleted=0", (run_id,)).fetchone()
            if run is None:
                raise KeyError(run_id)
            self._require_idle(db, run["project_id"])
            source = json.loads(run["source_status_json"])
            retained_source = {"demo": source["demo"]} if "demo" in source else {}
            db.execute("DELETE FROM captures WHERE run_id=?", (run_id,))
            db.execute("DELETE FROM observations WHERE run_id=?", (run_id,))
            db.execute("""UPDATE runs SET report_deleted=1,events_json='[]',counts_json='{}',
                source_status_json=?,error=NULL WHERE id=?""", (_json(retained_source), run_id))
            db.execute("INSERT OR IGNORE INTO artifact_cleanup VALUES(?)", (run_id,))
            return run["project_id"]

    def delete_project(self, project_id):
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            self._require_idle(db, project_id)
            # Cleanup requests deliberately have no FK: they survive deletion
            # and are retried after restart if filesystem removal is interrupted.
            db.execute("INSERT OR IGNORE INTO artifact_cleanup SELECT id FROM runs WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM observations WHERE run_id IN (SELECT id FROM runs WHERE project_id=?)", (project_id,))
            for table in ("captures", "generation_markers", "scan_schedules", "candidate_sources",
                          "domain_enrichment", "domain_states", "inventory", "runs"):
                db.execute(f"DELETE FROM {table} WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM projects WHERE id=?", (project_id,))

    def pending_artifact_cleanup(self):
        with self._connection() as db:
            return [row[0] for row in db.execute("SELECT run_id FROM artifact_cleanup")]

    def finish_artifact_cleanup(self, run_id):
        with self._connection(write=True) as db:
            db.execute("DELETE FROM artifact_cleanup WHERE run_id=?", (run_id,))

    @staticmethod
    def _dns_workers(workers):
        if workers is not None and (not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 128):
            raise ValueError("DNS workers must be an integer between 1 and 128, or null to inherit.")
        return workers

    def set_dns_workers(self, project_id, workers):
        """Set future scan concurrency; existing run snapshots remain unchanged."""
        workers = self._dns_workers(workers)
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            db.execute("UPDATE projects SET dns_workers=? WHERE id=?", (workers, project_id))
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    @staticmethod
    def _schedule_now(now=None):
        try:
            value = _now() if now is None else now
            moment = datetime.fromisoformat(value) if isinstance(value, str) else value
            if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
                raise ValueError
            return moment.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("Schedule time must be an aware ISO date or datetime.") from exc

    @staticmethod
    def _discovery_mode(mode):
        if not isinstance(mode, str) or mode not in {"enumerate", "cached"}:
            raise ValueError("Choose enumerate or cached for discovery_mode.")
        return mode

    def set_schedule(self, project_id, interval_hours, *, discovery_mode=None):
        """Persist an independent cadence: 0 disables, otherwise 1–8760 hours."""
        if (not isinstance(interval_hours, (int, float)) or isinstance(interval_hours, bool)
                or (interval_hours != 0 and not 1 <= interval_hours <= 8760)
                or not math.isfinite(interval_hours)):
            raise ValueError("Schedule interval must be 0 (off) or between 1 and 8760 hours.")
        interval = float(interval_hours)
        if discovery_mode is not None:
            discovery_mode = self._discovery_mode(discovery_mode)
        next_at = ((self._schedule_now() + timedelta(hours=interval)).isoformat(timespec="microseconds")
                   if interval else None)
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            # Compatibility for callers using the former single schedule.
            db.execute("DELETE FROM scan_schedules WHERE project_id=?", (project_id,))
            if discovery_mode == "cached" and not db.execute(
                    "SELECT 1 FROM inventory WHERE project_id=? AND kind='candidate' LIMIT 1", (project_id,)).fetchone():
                raise ValueError("No saved candidate inventory yet. Run an enumeration scan first.")
            db.execute("UPDATE projects SET schedule_interval_hours=?,schedule_next_run_at=? WHERE id=?",
                       (interval, next_at, project_id))
            if discovery_mode is not None:
                db.execute("UPDATE projects SET discovery_mode=? WHERE id=?", (discovery_mode, project_id))
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def set_schedules(self, project_id, intervals, *, discovery_mode, capture_modes=None):
        """Save both independent cadences and the manual scan's default mode."""
        mode = self._discovery_mode(discovery_mode)
        if set(intervals) != {"enumerate", "cached"}:
            raise ValueError("Provide both enumeration and saved-inventory schedules.")
        if capture_modes is not None:
            from .capture_changes import normalize_policy
            if set(capture_modes) != {"enumerate", "cached"}:
                raise ValueError("Provide capture modes for both schedules.")
            capture_modes = {key: normalize_policy(value)["mode"] for key, value in capture_modes.items()}
        for value in intervals.values():
            if (not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value)
                    or (value != 0 and not 1 <= value <= 8760)):
                raise ValueError("Each interval must be 0 (off) or between 1 and 8760 hours.")
        moment = self._schedule_now()
        with self._connection(write=True) as db:
            self._require_project(db, project_id)
            for schedule_mode, interval in intervals.items():
                old = db.execute("SELECT * FROM scan_schedules WHERE project_id=? AND discovery_mode=?",
                                 (project_id, schedule_mode)).fetchone()
                # Saving a new name/default mode must not postpone unchanged cadences.
                next_at = (old["next_run_at"] if old and old["interval_hours"] == interval else
                    (moment + timedelta(hours=interval)).isoformat(timespec="microseconds") if interval else None)
                capture_mode = (capture_modes[schedule_mode] if capture_modes is not None else
                                old["capture_mode"] if old else "changes")
                db.execute("INSERT OR REPLACE INTO scan_schedules(project_id,discovery_mode,interval_hours,next_run_at,capture_mode) VALUES(?,?,?,?,?)",
                           (project_id, schedule_mode, float(interval), next_at, capture_mode))
            db.execute("""UPDATE projects SET schedule_interval_hours=0,schedule_next_run_at=NULL,
                discovery_mode=? WHERE id=?""", (mode, project_id))
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def due_projects(self, now=None):
        """Return due projects; queue acceptance must precede advance_schedule."""
        deadline = self._schedule_now(now).isoformat(timespec="microseconds")
        with self._connection() as db:
            db.execute("BEGIN")
            rows = db.execute("""SELECT p.* FROM projects p WHERE (
                (p.schedule_interval_hours>0 AND p.schedule_next_run_at IS NOT NULL AND p.schedule_next_run_at<=?)
                OR EXISTS(SELECT 1 FROM scan_schedules s WHERE s.project_id=p.id AND s.interval_hours>0
                    AND s.next_run_at<=? AND (s.discovery_mode='enumerate' OR EXISTS(
                        SELECT 1 FROM inventory i WHERE i.project_id=p.id AND i.kind='candidate'))))
                AND NOT EXISTS(SELECT 1 FROM runs r WHERE r.project_id=p.id AND r.status='running')
                ORDER BY p.schedule_next_run_at,p.id""", (deadline, deadline)).fetchall()
            projects = [self._project(db, row) for row in rows]
            return [project for project in projects
                    if "demo" not in (project.get("last_run") or {}).get("source_status", {})]

    def advance_schedule(self, project_id, now=None, *, discovery_mode=None, capture_mode=None):
        """Advance after successful queue submission, without altering scan state.

        The worker serializes submission and this call. An unadvanced deadline
        remains due after restart, so interrupted queue submission can retry.
        """
        with self._connection(write=True) as db:
            project = self._require_project(db, project_id)
            mode = self._discovery_mode(discovery_mode or project["discovery_mode"])
            moment = self._schedule_now(now)
            schedules = db.execute("SELECT * FROM scan_schedules WHERE project_id=?", (project_id,)).fetchall()
            if schedules:
                for schedule in schedules:
                    # Full enumeration includes the saved-inventory DNS/web work.
                    # A cached scan must never defer the next enumeration.
                    if schedule["interval_hours"] and (mode == "enumerate" or schedule["discovery_mode"] == mode):
                        if (schedule["discovery_mode"] != mode and schedule["capture_mode"] == "full"
                                and capture_mode == "changes"):
                            continue
                        next_at = (moment + timedelta(hours=schedule["interval_hours"])).isoformat(timespec="microseconds")
                        db.execute("UPDATE scan_schedules SET next_run_at=? WHERE project_id=? AND discovery_mode=?",
                                   (next_at, project_id, schedule["discovery_mode"]))
                return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())
            interval = project["schedule_interval_hours"]
            if not interval or (mode == "cached" and project["discovery_mode"] == "enumerate"):
                return self._project(db, project)
            next_at = (moment + timedelta(hours=interval)).isoformat(timespec="microseconds")
            db.execute("UPDATE projects SET schedule_next_run_at=? WHERE id=?", (next_at, project_id))
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def bind_comparison_scope(self, project_id, scope):
        """Pin the resolver view once this project has an informative baseline."""
        if not isinstance(scope, dict):
            raise ValueError("DNS comparison settings must be a mapping.")
        try:
            scope_json = _json(scope)
        except (TypeError, ValueError) as exc:
            raise ValueError("DNS comparison settings must be JSON serializable.") from exc
        with self._connection(write=True) as db:
            project = self._require_project(db, project_id)
            if (project["baseline_run_id"] is not None
                    and project["comparison_scope_json"] is not None
                    and project["comparison_scope_json"] != scope_json):
                raise RuntimeError(
                    "DNS comparison settings changed. Create a new project/baseline "
                    "or keep the same resolvers, query types, and missing threshold."
                )
            db.execute("UPDATE projects SET comparison_scope_json=? WHERE id=?", (scope_json, project_id))
            return self._project(db, db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def inventory(self, project_id):
        with self._connection() as db:
            self._require_project(db, project_id)
            rows = db.execute("SELECT domain,kind FROM inventory WHERE project_id=? ORDER BY domain", (project_id,)).fetchall()
            return {"seeds": [r["domain"] for r in rows if r["kind"] == "seed"],
                    "candidates": [r["domain"] for r in rows if r["kind"] == "candidate"]}

    def has_candidate_inventory(self, project_id):
        """Check cache availability without loading a large candidate list."""
        with self._connection() as db:
            self._require_project(db, project_id)
            return db.execute("SELECT 1 FROM inventory WHERE project_id=? AND kind='candidate' LIMIT 1",
                              (project_id,)).fetchone() is not None

    @staticmethod
    def _generation_signature(signature):
        if not isinstance(signature, str) or not signature.strip() or len(signature) > 4096:
            raise ValueError("Generation signature must be nonempty text of at most 4096 characters.")
        return signature

    def generation_cache(self, project_id, signature):
        """Return seeds whose results for this generator signature were accepted.

        Candidate inventory and provenance remain the cached results. This
        marker alone never treats an interrupted or unaccepted run as cached.
        """
        signature = self._generation_signature(signature)
        with self._connection() as db:
            self._require_project(db, project_id)
            return {row[0] for row in db.execute(
                "SELECT seed FROM generation_markers WHERE project_id=? AND signature=?", (project_id, signature))}

    def start_run(self, project_id, *, dns_workers=None, discovery_mode=None, proxy_status=None, dns_route_key="direct", capture_mode=None, capture_defaults=None):
        dns_workers = self._dns_workers(dns_workers)
        with self._connection(write=True) as db:
            project = self._require_project(db, project_id)
            workers = self._dns_workers(project["dns_workers"] if dns_workers is None else dns_workers)
            mode = self._discovery_mode(project["discovery_mode"] if discovery_mode is None else discovery_mode)
            if mode == "cached" and not db.execute(
                    "SELECT 1 FROM inventory WHERE project_id=? AND kind='candidate' LIMIT 1", (project_id,)).fetchone():
                raise ValueError("No saved candidate inventory yet. Run an enumeration scan first.")
            if db.execute("SELECT 1 FROM runs WHERE project_id=? AND status='running'", (project_id,)).fetchone():
                raise RuntimeError("A scan is already running for this project.")
            from .title_filter import combine_policies
            capture_filter = combine_policies(self._global_capture_filter(db), json.loads(project["capture_filter_json"]))
            from .capture_changes import normalize_policy, PERFORMANCE_DEFAULTS
            capture_policy = normalize_policy(**json.loads(project["capture_policy_json"]))
            if capture_mode is not None:
                capture_policy = normalize_policy(**{**capture_policy, "mode": capture_mode})
            defaults = normalize_policy(**{**PERFORMANCE_DEFAULTS, **(capture_defaults or {})})
            for field in PERFORMANCE_DEFAULTS:
                if capture_policy[field] is None:
                    capture_policy[field] = defaults[field]
            capture_policy = normalize_policy(**capture_policy)
            run_id = str(uuid4())
            db.execute("""INSERT INTO runs(id,project_id,status,started_at,dns_workers,discovery_mode,proxy_status_json,dns_route_key,capture_filter_json,capture_policy_json)
                VALUES(?,?, 'running', ?,?,?,?,?,?,?)""",
                       (run_id, project_id, _now(), workers, mode, _json(proxy_status or {}), dns_route_key, _json(capture_filter), _json(capture_policy)))
            return self._run(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    @staticmethod
    def _sources_complete(source_status):
        for value in source_status.values():
            status = value.get("status", "unknown") if isinstance(value, dict) else value
            if status not in ("ok", "success", "completed", "skipped", "disabled", True):
                return False
        return True

    def finish_run(self, run_id, *, seeds, candidates, observations, source_status, missing_threshold=2, provenance=None, screenshots=None, generation=None):
        """Accept a scan atomically, retaining every previously known candidate.

        An omitted domain is unchecked, never absent. Unknown checks interrupt
        consecutive-negative counting. No event claims registration or deletion.
        """
        if not isinstance(missing_threshold, int) or isinstance(missing_threshold, bool) or missing_threshold < 2:
            raise ValueError("At least two negative checks are required to confirm missing domains.")
        if not isinstance(source_status, dict) or not isinstance(observations, dict):
            raise ValueError("Source status and observations must be mappings.")
        seeds = sorted({normalize_domain(domain) for domain in seeds})
        candidates = sorted({normalize_domain(domain) for domain in candidates})
        generation_signature, generated_seeds = None, set()
        if generation is not None:
            if not isinstance(generation, Mapping):
                raise ValueError("Generation metadata must be a mapping.")
            generation_signature = self._generation_signature(generation.get("signature"))
            if not isinstance(generation.get("seeds"), (list, tuple, set, frozenset)):
                raise ValueError("Generated seeds must be a list of domain names.")
            generated_seeds = {normalize_domain(seed) for seed in generation["seeds"]}
        normalized_screenshots = self._normalize_screenshots(screenshots)
        if provenance is not None and not isinstance(provenance, Mapping):
            raise ValueError("Candidate provenance must be a mapping.")
        normalized_provenance = {}
        for domain, sources in (provenance or {}).items():
            if isinstance(sources, str):
                raise ValueError("Candidate sources must be a list of seed domains.")
            domain = normalize_domain(domain)
            normalized_provenance.setdefault(domain, set()).update(normalize_domain(seed) for seed in sources)
        normalized = {}
        for domain, observation in observations.items():
            domain = normalize_domain(domain)
            if domain in normalized:
                raise ValueError("Duplicate normalized domain observations.")
            if not isinstance(observation, dict) or observation.get("status") not in {"resolved", "nxdomain", "noanswer", "unknown"}:
                raise ValueError("Unsupported DNS observation status.")
            status = observation["status"]
            records = normalize_records(observation.get("records", []))
            if status == "resolved" and not records:
                raise ValueError("A resolved observation requires DNS records.")
            if status != "resolved" and records:
                raise ValueError("Only resolved observations may contain DNS records.")
            error = observation.get("error")
            if error is not None and not isinstance(error, str):
                raise ValueError("Observation errors must be strings.")
            parking = observation.get("parking", {"status": "unknown"})
            if (not isinstance(parking, dict)
                    or parking.get("status") not in {"likely_parked", "not_detected", "unknown"}
                    or (parking.get("provider") is not None and not isinstance(parking["provider"], str))
                    or not isinstance(parking.get("evidence", []), list)
                    or not all(isinstance(item, str) for item in parking.get("evidence", []))):
                raise ValueError("Invalid domain parking observation.")
            parking = {"status": parking["status"], "provider": parking.get("provider"), "evidence": parking.get("evidence", [])}
            if status != "resolved":
                parking = {"status": "unknown", "provider": None, "evidence": []}
            normalized[domain] = {"status": status, "records": records, "error": error, "parking": parking}
        source_json = _json(source_status)
        with self._connection(write=True) as db:
            run = self._require_running(db, run_id)
            project_id = run["project_id"]
            project = self._require_project(db, project_id)
            db.executemany("INSERT OR IGNORE INTO inventory VALUES(?,?, 'seed')", [(project_id, d) for d in seeds])
            db.executemany("INSERT OR IGNORE INTO inventory VALUES(?,?, 'candidate')", [(project_id, d) for d in candidates])
            candidate_set = {row[0] for row in db.execute("SELECT domain FROM inventory WHERE project_id=? AND kind='candidate'", (project_id,))}
            if not normalized.keys() <= candidate_set:
                raise ValueError("Observations must belong to the candidate inventory.")
            if not normalized_screenshots.keys() <= candidate_set:
                raise ValueError("Screenshots must belong to the candidate inventory.")
            seed_set = {row[0] for row in db.execute("SELECT domain FROM inventory WHERE project_id=? AND kind='seed'", (project_id,))}
            if not generated_seeds <= seed_set:
                raise ValueError("Generation markers must belong to the seed inventory.")
            if (not normalized_provenance.keys() <= candidate_set
                    or any(not sources <= seed_set for sources in normalized_provenance.values())):
                raise ValueError("Provenance must link known candidates to known seed domains.")
            db.executemany("INSERT OR IGNORE INTO candidate_sources VALUES(?,?,?)",
                           [(project_id, domain, seed) for domain, sources in normalized_provenance.items() for seed in sorted(sources)])
            db.executemany("INSERT OR IGNORE INTO domain_states(project_id,domain) VALUES(?,?)", [(project_id, d) for d in sorted(candidate_set)])
            route_changed = run["dns_route_key"] != project["dns_route_key"]
            baseline = project["baseline_run_id"] is None or route_changed
            informative = any(o["status"] != "unknown" for o in normalized.values())
            preceding = db.execute(
                "SELECT status FROM runs WHERE project_id=? AND id<>? ORDER BY started_at DESC, rowid DESC LIMIT 1",
                (project_id, run_id),
            ).fetchone()
            interrupted_sequence = preceding is not None and preceding["status"] in {"failed", "cancelled"}
            events = []
            finished_at = _now()
            for domain, observation in sorted(normalized.items()):
                previous = self._state(db.execute("SELECT * FROM domain_states WHERE project_id=? AND domain=?", (project_id, domain)).fetchone())
                if route_changed:
                    previous.update(status="unknown", missing_count=0)
                current = dict(previous)
                if interrupted_sequence:
                    current["missing_count"] = 0
                current.update(last_checked=finished_at, last_error=observation["error"], latest_observation=observation["status"])
                kind, detail = None, None
                if observation["status"] == "resolved":
                    current.update(status="resolved", records=observation["records"], missing_count=0,
                                   first_seen=previous["first_seen"] or finished_at, last_seen=finished_at)
                    if previous["first_seen"] is None:
                        kind, detail = "newly_observed", "First successful DNS observation; this does not establish a registration date."
                    elif previous["status"] == "missing":
                        kind, detail = "reappeared", "DNS resolved after a confirmed period of negative observations."
                    elif previous["records"] != current["records"]:
                        kind, detail = "records_changed", "The normalized DNS record set changed."
                elif observation["status"] in {"nxdomain", "noanswer"}:
                    current["missing_count"] += 1
                    if previous["status"] == "missing" or current["missing_count"] >= missing_threshold:
                        current["status"] = "missing"
                        if previous["status"] != "missing" and previous["first_seen"] is not None:
                            kind = "missing_confirmed"
                            detail = f"{current['missing_count']} consecutive explicit negative DNS observations."
                    else:
                        current["status"] = "pending_missing"
                else:
                    current["missing_count"] = 0
                    current["status"] = "missing" if previous["status"] == "missing" else "unknown"
                if kind and not baseline:
                    events.append({"domain": domain, "kind": kind, "before": previous["records"],
                                   "after": [] if kind == "missing_confirmed" else current["records"], "detail": detail})
                db.execute("""UPDATE domain_states SET status=?,records_json=?,first_seen=?,last_seen=?,
                    last_checked=?,last_error=?,missing_count=?,latest_observation=? WHERE project_id=? AND domain=?""",
                    (current["status"], _json(current["records"]), current["first_seen"], current["last_seen"],
                     current["last_checked"], current["last_error"], current["missing_count"], current["latest_observation"], project_id, domain))
                db.execute("INSERT INTO observations VALUES(?,?,?,?,?)",
                           (run_id, domain, observation["status"], _json(observation["records"]), observation["error"]))
                parking = observation["parking"]
                db.execute("""INSERT INTO domain_enrichment VALUES(?,?,?,?,?,?)
                    ON CONFLICT(project_id,domain) DO UPDATE SET
                    parking_status=excluded.parking_status,parking_provider=excluded.parking_provider,
                    parking_evidence_json=excluded.parking_evidence_json,parking_checked_at=excluded.parking_checked_at""",
                    (project_id, domain, parking["status"], parking["provider"], _json(parking["evidence"]), finished_at))
            # An unchecked scan interrupts the sequence as well: two negative
            # results separated by an incomplete check are not consecutive.
            for domain in candidate_set - normalized.keys():
                db.execute("""UPDATE domain_states SET missing_count=0,
                    status=CASE WHEN status='missing' THEN 'missing' ELSE 'unknown' END
                    WHERE project_id=? AND domain=?""", (project_id, domain))
                db.execute("""UPDATE domain_enrichment SET parking_status='unknown',parking_provider=NULL,
                    parking_evidence_json='[]',parking_checked_at=NULL WHERE project_id=? AND domain=?""", (project_id, domain))
                if route_changed:
                    db.execute("UPDATE domain_states SET status='unknown' WHERE project_id=? AND domain=?", (project_id, domain))
            counts = {"seeds": db.execute("SELECT COUNT(*) FROM inventory WHERE project_id=? AND kind='seed'", (project_id,)).fetchone()[0],
                      "candidates": len(candidate_set), "checked": len(normalized), "events": len(events)}
            counts.update({status: sum(o["status"] == status for o in normalized.values())
                           for status in ("resolved", "nxdomain", "noanswer", "unknown")})
            counts["unchecked"] = len(candidate_set) - len(normalized)
            for kind in ("newly_observed", "records_changed", "missing_confirmed", "reappeared"):
                counts[kind] = sum(event["kind"] == kind for event in events)
            for state in ("missing", "pending_missing"):
                counts[state] = db.execute("SELECT COUNT(*) FROM domain_states WHERE project_id=? AND status=?", (project_id, state)).fetchone()[0]
            if screenshots is not None:
                attempts = [(domain, attempt) for domain, entries in normalized_screenshots.items() for attempt in entries]
                db.executemany("""INSERT INTO captures(run_id,project_id,domain,scheme,status,relative_path,
                    url,title,http_status,error,captured_at,visual_json,preflight_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [(run_id, project_id, domain, attempt["scheme"], attempt["status"], attempt["relative_path"],
                      attempt["url"], attempt["title"], attempt["http_status"], attempt["error"], attempt["captured_at"], _json(attempt["visual"]), _json(attempt["preflight"]))
                     for domain, attempt in attempts])
                counts["screenshots_total"] = len(attempts)
                counts["screenshots_title_filtered"] = sum(attempt["preflight"].get("skip_reason") == "title_rule" for _, attempt in attempts)
                counts["screenshots_browser_title_filtered"] = sum(attempt["preflight"].get("report_exclusion") == "browser_title_rule" for _, attempt in attempts)
                counts["screenshots_body_duplicates"] = sum(attempt["preflight"].get("skip_reason") == "duplicate_body" for _, attempt in attempts)
                counts["screenshots_text_unchanged"] = sum(attempt["preflight"].get("skip_reason") == "unchanged_content" for _, attempt in attempts)
                counts["screenshots_title_unchanged"] = sum(attempt["preflight"].get("skip_reason") == "unchanged_title" for _, attempt in attempts)
                for capture_status in ("captured", "failed", "unavailable", "skipped"):
                    counts["screenshots_" + capture_status] = sum(attempt["status"] == capture_status for _, attempt in attempts)
                for image_change in ("first_capture", "changed", "unchanged", "uncertain"):
                    counts["images_" + image_change] = sum(attempt["visual"].get("change") == image_change for _, attempt in attempts)
            complete = self._sources_complete(source_status) and not counts["unknown"] and not counts["unchecked"]
            status = "completed" if complete else "partial"
            if generation_signature is not None:
                db.executemany("""INSERT OR IGNORE INTO generation_markers
                    (project_id,signature,seed,run_id,generated_at) VALUES(?,?,?,?,?)""",
                    [(project_id, generation_signature, seed, run_id, finished_at) for seed in sorted(generated_seeds)])
            db.execute("""UPDATE runs SET status=?,finished_at=?,is_baseline=?,events_json=?,counts_json=?,
                source_status_json=? WHERE id=?""", (status, finished_at, baseline and informative, _json(events), _json(counts), source_json, run_id))
            if baseline and informative:
                db.execute("UPDATE projects SET baseline_run_id=?,dns_route_key=? WHERE id=?", (run_id, run["dns_route_key"], project_id))
            return self._run(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def fail_run(self, run_id, error, *, source_status=None):
        source_json = _json(source_status) if source_status is not None else None
        with self._connection(write=True) as db:
            self._require_running(db, run_id)
            db.execute("UPDATE runs SET status='failed',finished_at=?,error=?,source_status_json=COALESCE(?,source_status_json) WHERE id=?",
                       (_now(), str(error), source_json, run_id))
            return self._run(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def cancel_run(self, run_id, reason="Scan cancelled by user."):
        """Cancel a running attempt; terminal attempts are returned unchanged."""
        with self._connection(write=True) as db:
            run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if run is None:
                raise KeyError(run_id)
            if run["status"] != "running":
                return self._run(run)
            db.execute("UPDATE runs SET status='cancelled',finished_at=?,error=? WHERE id=?", (_now(), str(reason), run_id))
            return self._run(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def recover_interrupted_runs(self):
        """Mark leftover running jobs failed at service startup; return their count."""
        with self._connection(write=True) as db:
            result = db.execute("""UPDATE runs SET status='failed',finished_at=?,
                error='Scan interrupted before completion; accepted observations were preserved.'
                WHERE status='running'""", (_now(),))
            return result.rowcount

    def get_run(self, run_id):
        with self._connection() as db:
            return self._run(db.execute("SELECT * FROM runs WHERE id=? AND report_deleted=0", (run_id,)).fetchone())

    def list_runs(self, project_id, limit=None, include_events=True, *, offset=0):
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise ValueError("Run limit must be a positive integer.")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("Run offset must be a nonnegative integer.")
        columns = "*" if include_events else self._RUN_SUMMARY_COLUMNS
        query = f"SELECT {columns} FROM runs WHERE project_id=? AND report_deleted=0 ORDER BY started_at DESC, rowid DESC"
        parameters = [project_id]
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(limit)
        elif offset:
            query += " LIMIT -1"
        if offset:
            query += " OFFSET ?"
            parameters.append(offset)
        with self._connection() as db:
            self._require_project(db, project_id)
            return [self._run(row) for row in db.execute(query, parameters)]

    def get_domains(self, project_id):
        return self.export_domains(project_id)

    def get_domain(self, project_id, domain):
        try:
            domain = normalize_domain(domain)
        except ValueError:
            return None
        with self._connection() as db:
            db.execute("BEGIN")
            self._require_project(db, project_id)
            row = db.execute(self._STATE_QUERY + " WHERE d.project_id=? AND d.domain=?", (project_id, domain)).fetchone()
            return self._public_states(db, project_id, [row])[0] if row is not None else None

    def get_capture(self, run_id, domain, scheme):
        try:
            domain = normalize_domain(domain)
        except ValueError:
            return None
        if scheme not in ("http", "https"):
            return None
        with self._connection() as db:
            return self._capture(db.execute("SELECT * FROM captures WHERE run_id=? AND domain=? AND scheme=?",
                                           (run_id, domain, scheme)).fetchone())

    def list_captures(self, project_id, domain, limit=20):
        domain = normalize_domain(domain)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("Capture history limit must be between 1 and 1000.")
        with self._connection() as db:
            self._require_project(db, project_id)
            return [self._capture(row) for row in db.execute("""SELECT * FROM captures
                WHERE project_id=? AND domain=? ORDER BY captured_at DESC,rowid DESC LIMIT ?""", (project_id, domain, limit))]

    def text_review_context(self, project_id, run_id):
        """Only seeds and this run's capture-domain context, never full inventory."""
        with self._connection() as db:
            db.execute("BEGIN")
            self._require_project(db, project_id)
            seeds = {row["domain"] for row in db.execute(
                "SELECT domain FROM inventory WHERE project_id=? AND kind='seed'", (project_id,))}
            states = {row["domain"]: {"parking": {"status": row["parking_status"]}, "sources": []}
                for row in db.execute("""SELECT DISTINCT c.domain,e.parking_status FROM captures c
                    LEFT JOIN domain_enrichment e ON e.project_id=c.project_id AND e.domain=c.domain
                    WHERE c.project_id=? AND c.run_id=?""", (project_id, run_id))}
            for row in db.execute("""SELECT DISTINCT s.domain,s.seed FROM captures c JOIN candidate_sources s
                ON s.project_id=c.project_id AND s.domain=c.domain WHERE c.project_id=? AND c.run_id=?
                ORDER BY s.domain,s.seed""", (project_id, run_id)):
                states[row["domain"]]["sources"].append(row["seed"])
            return seeds, states

    def list_run_captures(self, run_id):
        with self._connection() as db:
            return [self._capture(row) for row in db.execute(
                "SELECT * FROM captures WHERE run_id=? ORDER BY domain,scheme", (run_id,))]

    def capture_baselines(self, project_id):
        """Bulk metadata only: previous accepted checks and latest real images."""
        with self._connection() as db:
            db.execute("BEGIN")
            previous_run = db.execute("""SELECT id FROM runs WHERE project_id=?
                AND status IN ('completed','partial') ORDER BY started_at DESC,rowid DESC LIMIT 1""", (project_id,)).fetchone()
            baselines = {}
            if previous_run:
                for row in db.execute("SELECT * FROM captures WHERE run_id=?", (previous_run["id"],)):
                    baselines.setdefault((row["domain"], row["scheme"]), {})["previous"] = self._capture(row)
            for row in db.execute("""SELECT * FROM (SELECT c.*,r.proxy_status_json AS routes_json,
                ROW_NUMBER() OVER(PARTITION BY c.domain,c.scheme ORDER BY c.captured_at DESC,c.rowid DESC) AS image_rank
                FROM captures c JOIN runs r ON r.id=c.run_id WHERE c.project_id=? AND c.status='captured')
                WHERE image_rank=1""", (project_id,)):
                baseline = baselines.setdefault((row["domain"], row["scheme"]), {})
                image = self._capture(row)
                image.pop("image_rank", None)
                baseline["route"] = json.loads(image.pop("routes_json")).get("capture", {})
                baseline["image"] = image
            return baselines

    def latest_successful_capture(self, project_id, domain, scheme):
        domain = normalize_domain(domain)
        if scheme not in ("http", "https"):
            return None
        with self._connection() as db:
            return self._capture(db.execute("""SELECT * FROM captures WHERE project_id=? AND domain=?
                AND scheme=? AND status='captured' ORDER BY captured_at DESC,rowid DESC LIMIT 1""",
                (project_id, domain, scheme)).fetchone())

    def previous_successful_capture(self, run_id, domain, scheme):
        """Metadata for manual before/after viewing; no image comparison."""
        domain = normalize_domain(domain)
        if scheme not in ("http", "https"):
            return None
        with self._connection() as db:
            return self._capture(db.execute("""SELECT older.* FROM captures newer
                JOIN captures older ON older.project_id=newer.project_id
                    AND older.domain=newer.domain AND older.scheme=newer.scheme
                WHERE newer.run_id=? AND newer.domain=? AND newer.scheme=?
                    AND older.status='captured' AND older.rowid<newer.rowid
                ORDER BY older.rowid DESC LIMIT 1""", (run_id, domain, scheme)).fetchone())

    def save_capture_review(self, run_id, domain, scheme, review, *, text_only=False):
        if not isinstance(review, dict):
            raise ValueError("AI assessment must be a JSON object.")
        for field in ("provider", "model", "summary"):
            if not isinstance(review.get(field), str) or not review[field].strip():
                raise ValueError(f"AI assessment requires {field}.")
        if review.get("risk") not in ("low", "medium", "high", "uncertain"):
            raise ValueError("AI assessment risk must be low, medium, high, or uncertain.")
        if review.get("changed") is not None and not isinstance(review["changed"], bool):
            raise ValueError("AI changed assessment must be boolean or null.")
        confidence = review.get("confidence")
        if confidence is not None and (not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1):
            raise ValueError("AI confidence must be between 0 and 1.")
        assessment = {field: review.get(field) for field in ("provider", "model", "summary", "risk", "changed", "confidence")}
        if text_only:
            if not isinstance(review.get("content_sha256"), str) or len(review["content_sha256"]) != 64:
                raise ValueError("A text content_sha256 is required; image assessments are disabled on the API.")
            assessment.update(kind="text", content_sha256=review["content_sha256"])
        assessment["reviewed_at"] = _now()
        serialized = _json(assessment)
        if len(serialized) > 16384:
            raise ValueError("AI assessment is too large.")
        with self._connection(write=True) as db:
            domain = normalize_domain(domain)
            row = db.execute("SELECT * FROM captures WHERE run_id=? AND domain=? AND scheme=?", (run_id, domain, scheme)).fetchone()
            capture = self._capture(row) if row else None
            if text_only:
                from .capture_changes import text_complete
                if not capture or not text_complete(capture["preflight"]) or capture["preflight"].get("content_sha256") != review["content_sha256"]:
                    raise ValueError("Assessment must match this scan's complete saved text fingerprint.")
            elif not capture or capture["status"] != "captured":
                raise ValueError("A successful capture is required for an image assessment.")
            db.execute("UPDATE captures SET analysis_json=? WHERE run_id=? AND domain=? AND scheme=?", (serialized, run_id, domain, scheme))
            return self._capture(db.execute("SELECT * FROM captures WHERE run_id=? AND domain=? AND scheme=?",
                                           (run_id, normalize_domain(domain), scheme)).fetchone())

    def domain_counts(self, project_id):
        with self._connection() as db:
            self._require_project(db, project_id)
            counts = dict.fromkeys(("total", "resolved", "pending_missing", "missing", "unknown", "likely_parked"), 0)
            for row in db.execute("SELECT status,COUNT(*) AS count FROM domain_states WHERE project_id=? GROUP BY status", (project_id,)):
                counts[row["status"]] = row["count"]
                counts["total"] += row["count"]
            counts["likely_parked"] = db.execute("""SELECT COUNT(*) FROM domain_states d
                JOIN domain_enrichment e ON e.project_id=d.project_id AND e.domain=d.domain
                WHERE d.project_id=? AND d.status='resolved' AND e.parking_status='likely_parked'""", (project_id,)).fetchone()[0]
            return counts

    @staticmethod
    def _domain_filter(project_id, *, query="", status="", seed="", hide_parked=False, include_seeds=True):
        if (not isinstance(query, str) or not isinstance(status, str)
                or status not in {"", "resolved", "pending_missing", "missing", "unknown"}):
            raise ValueError("Invalid domain search or status filter.")
        if not isinstance(seed, str) or not isinstance(hide_parked, bool) or not isinstance(include_seeds, bool):
            raise ValueError("Invalid domain source or parking filter.")
        where = "d.project_id=?"
        parameters = [project_id]
        if query:
            literal = query.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where += " AND d.domain LIKE ? ESCAPE '\\'"
            parameters.append("%" + literal + "%")
        if status:
            where += " AND d.status=?"
            parameters.append(status)
        if seed == "__unattributed__":
            where += " AND NOT EXISTS(SELECT 1 FROM candidate_sources s WHERE s.project_id=d.project_id AND s.domain=d.domain)"
        elif seed:
            seed = normalize_domain(seed)
            where += " AND EXISTS(SELECT 1 FROM candidate_sources s WHERE s.project_id=d.project_id AND s.domain=d.domain AND s.seed=?)"
            parameters.append(seed)
        if hide_parked:
            where += " AND NOT EXISTS(SELECT 1 FROM domain_enrichment e WHERE e.project_id=d.project_id AND e.domain=d.domain AND e.parking_status='likely_parked')"
        if not include_seeds:
            where += " AND NOT EXISTS(SELECT 1 FROM inventory i WHERE i.project_id=d.project_id AND i.domain=d.domain AND i.kind='seed')"
        return where, parameters

    def query_domains(self, project_id, *, query="", status="", seed="", hide_parked=False, include_seeds=True, limit=100, offset=0):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("Page limit must be between 1 and 1000.")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("Page offset must be a nonnegative integer.")
        where, parameters = self._domain_filter(project_id, query=query, status=status, seed=seed,
                                                  hide_parked=hide_parked, include_seeds=include_seeds)
        with self._connection() as db:
            db.execute("BEGIN")
            self._require_project(db, project_id)
            total = db.execute(f"SELECT COUNT(*) FROM domain_states d WHERE {where}", parameters).fetchone()[0]
            rows = db.execute(
                self._STATE_QUERY + f" WHERE {where} ORDER BY d.domain LIMIT ? OFFSET ?",
                [*parameters, limit, offset],
            ).fetchall()
            return {"items": self._public_states(db, project_id, rows), "total": total}

    def export_domains(self, project_id, *, query="", status="", seed="", hide_parked=False, include_seeds=True):
        """Read the entire filtered view, including metadata, in one snapshot."""
        where, parameters = self._domain_filter(project_id, query=query, status=status, seed=seed,
                                                  hide_parked=hide_parked, include_seeds=include_seeds)
        with self._connection() as db:
            db.execute("BEGIN")
            self._require_project(db, project_id)
            rows = db.execute(self._STATE_QUERY + f" WHERE {where} ORDER BY d.domain", parameters).fetchall()
            return self._public_states(db, project_id, rows)

    def source_groups(self, project_id, *, status="resolved", hide_parked=False, include_seeds=False, query=""):
        where, parameters = self._domain_filter(project_id, query=query, status=status,
                                                  hide_parked=hide_parked, include_seeds=include_seeds)
        with self._connection() as db:
            self._require_project(db, project_id)
            rows = db.execute(f"""SELECT COALESCE(s.seed,'__unattributed__') AS seed,COUNT(*) AS total
                FROM domain_states d LEFT JOIN candidate_sources s
                    ON s.project_id=d.project_id AND s.domain=d.domain
                WHERE {where} GROUP BY s.seed ORDER BY seed""", parameters)
            return [dict(row) for row in rows]
