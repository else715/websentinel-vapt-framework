import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DB_PATH = Path(os.environ.get("WEBSENTINEL_DB", "websentinel.db"))


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('domain', 'ip')),
                authorization_acknowledged INTEGER NOT NULL CHECK (authorization_acknowledged = 1),
                in_scope INTEGER NOT NULL DEFAULT 1 CHECK (in_scope IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, host)
            );
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                root_target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
                hostname TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'candidate' CHECK (state IN ('candidate', 'approved', 'rejected')),
                discovery_source TEXT NOT NULL,
                discovery_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                http_status TEXT NOT NULL DEFAULT '',
                page_title TEXT NOT NULL DEFAULT '',
                technologies TEXT NOT NULL DEFAULT '[]',
                last_probed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, hostname)
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                scan_type TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'queued',
                options_summary TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                finished_at TEXT,
                error_summary TEXT NOT NULL DEFAULT '',
                result_summary TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                asset TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'Informational',
                status TEXT NOT NULL DEFAULT 'unreviewed',
                description TEXT NOT NULL DEFAULT '',
                remediation TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                scanner_import_id INTEGER,
                cwe TEXT NOT NULL DEFAULT '',
                cvss_score TEXT NOT NULL DEFAULT '',
                cvss_vector TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '',
                raw_tool_data TEXT NOT NULL DEFAULT '',
                reference_urls TEXT NOT NULL DEFAULT '',
                owasp_mapping TEXT NOT NULL DEFAULT '',
                mitre_mapping TEXT NOT NULL DEFAULT '',
                rag_analysis TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scanner_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                tool TEXT NOT NULL,
                filename TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL,
                raw_output TEXT NOT NULL,
                imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(scan_id, sha256)
            );
            CREATE TABLE IF NOT EXISTS asset_probes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                url TEXT NOT NULL DEFAULT '',
                status_code TEXT NOT NULL DEFAULT '',
                page_title TEXT NOT NULL DEFAULT '',
                technologies TEXT NOT NULL DEFAULT '[]',
                raw_output TEXT NOT NULL,
                probed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                address TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, service TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                url TEXT NOT NULL, method TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'katana', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(scan_id, url, method)
            );
            CREATE TABLE IF NOT EXISTS mapping_documents (
                id TEXT PRIMARY KEY,
                framework TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                source_url TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assistant_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                content TEXT NOT NULL,
                sources TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        finding_columns = {row["name"] for row in db.execute("PRAGMA table_info(findings)")}
        migrations = {
            "scanner_import_id": "ALTER TABLE findings ADD COLUMN scanner_import_id INTEGER",
            "cwe": "ALTER TABLE findings ADD COLUMN cwe TEXT NOT NULL DEFAULT ''",
            "cvss_score": "ALTER TABLE findings ADD COLUMN cvss_score TEXT NOT NULL DEFAULT ''",
            "cvss_vector": "ALTER TABLE findings ADD COLUMN cvss_vector TEXT NOT NULL DEFAULT ''",
            "evidence": "ALTER TABLE findings ADD COLUMN evidence TEXT NOT NULL DEFAULT ''",
            "raw_tool_data": "ALTER TABLE findings ADD COLUMN raw_tool_data TEXT NOT NULL DEFAULT ''",
            "reference_urls": "ALTER TABLE findings ADD COLUMN reference_urls TEXT NOT NULL DEFAULT ''",
            "owasp_mapping": "ALTER TABLE findings ADD COLUMN owasp_mapping TEXT NOT NULL DEFAULT ''",
            "mitre_mapping": "ALTER TABLE findings ADD COLUMN mitre_mapping TEXT NOT NULL DEFAULT ''",
            "rag_analysis": "ALTER TABLE findings ADD COLUMN rag_analysis TEXT NOT NULL DEFAULT ''",
        }
        for column, statement in migrations.items():
            if column not in finding_columns:
                db.execute(statement)
        scan_columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)")}
        if "result_summary" not in scan_columns:
            db.execute("ALTER TABLE scans ADD COLUMN result_summary TEXT NOT NULL DEFAULT ''")
        db.execute(
            "INSERT OR IGNORE INTO assets(project_id, root_target_id, target_id, hostname, state, discovery_source) SELECT project_id, id, id, host, 'approved', 'manual' FROM targets"
        )


def audit(project_id: int | None, action: str, details: str = "") -> None:
    with connect() as db:
        db.execute(
            "INSERT INTO audit_events(project_id, action, details) VALUES (?, ?, ?)",
            (project_id, action, details[:500]),
        )
