import hashlib
import json
from urllib.parse import urlsplit

from app.database import audit, connect
from app.scanners.discovery import enumerate_subdomains, probe_approved_hosts
from app.scanners.importers import parse_output
from app.scanners.tool_adapters import (parse_jsonl, parse_nmap_xml, run_katana_crawl,
                                        run_nmap_inventory, run_nuclei_scan, run_zap_baseline)


def _begin_scan(scan_id: int):
    with connect() as db:
        scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            return None
        db.execute("UPDATE scans SET state='running', started_at=CURRENT_TIMESTAMP WHERE id=?", (scan_id,))
        return dict(scan)


def _finish_failed(scan_id: int, project_id: int, message: str) -> None:
    safe_message = message.strip()[:500] or "Scanner execution failed."
    with connect() as db:
        db.execute(
            "UPDATE scans SET state='failed', finished_at=CURRENT_TIMESTAMP, error_summary=? WHERE id=?",
            (safe_message, scan_id),
        )
    audit(project_id, "discovery.failed", f"scan_id={scan_id};error={safe_message}")


def execute_subfinder_scan(scan_id: int, target_id: int) -> None:
    scan = _begin_scan(scan_id)
    if scan is None:
        return
    with connect() as db:
        target = db.execute(
            "SELECT * FROM targets WHERE id=? AND project_id=? AND in_scope=1 AND authorization_acknowledged=1",
            (target_id, scan["project_id"]),
        ).fetchone()
    if target is None or target["kind"] != "domain":
        _finish_failed(scan_id, scan["project_id"], "The registered root domain is no longer in scope.")
        return
    try:
        discovered, raw_output = enumerate_subdomains(target["host"])
        digest = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()
        with connect() as db:
            imported = db.execute(
                "INSERT INTO scanner_imports(scan_id, tool, filename, sha256, raw_output) VALUES (?, 'subfinder', 'subfinder-output.txt', ?, ?)",
                (scan_id, digest, raw_output),
            )
            import_id = imported.lastrowid
            for hostname in discovered:
                db.execute(
                    "INSERT OR IGNORE INTO assets(project_id, root_target_id, hostname, state, discovery_source, discovery_scan_id) VALUES (?, ?, ?, 'candidate', 'subfinder', ?)",
                    (scan["project_id"], target_id, hostname, scan_id),
                )
            db.execute(
                "UPDATE scans SET state='completed', finished_at=CURRENT_TIMESTAMP, result_summary=? WHERE id=?",
                (f"Subfinder found {len(discovered)} in-scope subdomain candidates. Original output import #{import_id} retained.", scan_id),
            )
        audit(scan["project_id"], "discovery.completed", f"scan_id={scan_id};tool=subfinder;candidates={len(discovered)}")
    except Exception as exc:
        _finish_failed(scan_id, scan["project_id"], str(exc))


def execute_httpx_scan(scan_id: int, project_id: int) -> None:
    scan = _begin_scan(scan_id)
    if scan is None:
        return
    with connect() as db:
        targets = db.execute(
            "SELECT * FROM targets WHERE project_id=? AND in_scope=1 AND authorization_acknowledged=1 ORDER BY host LIMIT 51",
            (project_id,),
        ).fetchall()
    if len(targets) > 50:
        _finish_failed(scan_id, project_id, "The HTTP inventory is limited to 50 approved hosts per run.")
        return
    if not targets:
        _finish_failed(scan_id, project_id, "There are no approved in-scope hosts to probe.")
        return
    hosts = [target["host"] for target in targets]
    try:
        results, raw_output = probe_approved_hosts(hosts)
        digest = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()
        target_by_host = {target["host"]: target for target in targets}
        with connect() as db:
            imported = db.execute(
                "INSERT INTO scanner_imports(scan_id, tool, filename, sha256, raw_output) VALUES (?, 'httpx', 'httpx-output.jsonl', ?, ?)",
                (scan_id, digest, raw_output),
            )
            for item in results:
                target = target_by_host.get(item["host"])
                if target is None:
                    continue
                tech_json = json.dumps(item["technologies"], ensure_ascii=False)
                db.execute(
                    "INSERT INTO assets(project_id, root_target_id, target_id, hostname, state, discovery_source, http_status, page_title, technologies, last_probed_at) VALUES (?, ?, ?, ?, 'approved', 'manual-or-approved-scope', ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(project_id, hostname) DO UPDATE SET target_id=excluded.target_id, state='approved', http_status=excluded.http_status, page_title=excluded.page_title, technologies=excluded.technologies, last_probed_at=CURRENT_TIMESTAMP",
                    (project_id, target["id"], target["id"], item["host"], item["status_code"], item["title"], tech_json),
                )
                db.execute(
                    "INSERT INTO asset_probes(project_id, target_id, scan_id, url, status_code, page_title, technologies, raw_output) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (project_id, target["id"], scan_id, item["url"], item["status_code"], item["title"], tech_json, item["raw"]),
                )
            db.execute(
                "UPDATE scans SET state='completed', finished_at=CURRENT_TIMESTAMP, result_summary=? WHERE id=?",
                (f"httpx returned {len(results)} live-host observations. Original output import #{imported.lastrowid} retained; private IP destinations are excluded by the profile.", scan_id),
            )
        audit(project_id, "discovery.completed", f"scan_id={scan_id};tool=httpx;observations={len(results)}")
    except Exception as exc:
        _finish_failed(scan_id, project_id, str(exc))


def execute_tool_scan(scan_id: int, target_id: int, tool: str) -> None:
    scan = _begin_scan(scan_id)
    if scan is None:
        return
    with connect() as db:
        target = db.execute("SELECT * FROM targets WHERE id=? AND project_id=? AND in_scope=1 AND authorization_acknowledged=1", (target_id, scan["project_id"])).fetchone()
    if target is None:
        _finish_failed(scan_id, scan["project_id"], "Target is no longer approved and in scope.")
        return
    try:
        if tool == "nmap":
            if target["kind"] != "ip":
                raise RuntimeError("Nmap inventory requires an explicitly registered IP target.")
            raw = run_nmap_inventory(target["host"])
            records = parse_nmap_xml(raw)
            file_name = "nmap.xml"
        else:
            web_url = "https://" + target["host"]
            with connect() as db:
                latest = db.execute("SELECT url FROM asset_probes WHERE target_id=? AND url!='' ORDER BY id DESC LIMIT 1", (target_id,)).fetchone()
            if latest:
                candidate = latest["url"]
                if urlsplit(candidate).hostname == target["host"]:
                    web_url = candidate
            if tool == "katana":
                raw = run_katana_crawl(web_url)
                records = parse_jsonl(raw, "Katana")
                file_name = "katana.jsonl"
            elif tool == "nuclei":
                raw = run_nuclei_scan(web_url)
                records = parse_output("nuclei", raw)
                file_name = "nuclei.jsonl"
            elif tool == "zap":
                raw = run_zap_baseline(web_url)
                records = parse_output("zap", raw)
                file_name = "zap.json"
            else:
                raise RuntimeError("Unknown tool adapter.")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        with connect() as db:
            imported = db.execute("INSERT INTO scanner_imports(scan_id, tool, filename, sha256, raw_output) VALUES (?, ?, ?, ?, ?)", (scan_id, tool, file_name, digest, raw))
            if tool == "nmap":
                for item in records:
                    db.execute("INSERT INTO ports(project_id,target_id,scan_id,address,protocol,port,service,product,version) VALUES (?,?,?,?,?,?,?,?,?)", (scan["project_id"],target_id,scan_id,item["address"],item["protocol"],int(item["port"]),item["service"],item["product"],item["version"]))
            elif tool == "katana":
                for item in records[:1000]:
                    url = str(item.get("request", {}).get("endpoint") or item.get("url") or "")[:2000]
                    if url and urlsplit(url).hostname == target["host"]:
                        db.execute("INSERT OR IGNORE INTO endpoints(project_id,target_id,scan_id,url,method) VALUES (?,?,?,?,?)", (scan["project_id"],target_id,scan_id,url,str(item.get("request", {}).get("method") or "GET")[:20]))
            else:
                for item in records:
                    db.execute("INSERT INTO findings(scan_id,title,asset,severity,status,description,remediation,source,scanner_import_id,cwe,cvss_score,cvss_vector,evidence,raw_tool_data,reference_urls) VALUES (?,?,?,?,'unreviewed',?,?,?,?,?,?,?,?,?,?)", (scan_id,item["title"],item["asset"],item["severity"],item["description"],item["remediation"],item["source"],imported.lastrowid,item["cwe"],item["cvss_score"],item["cvss_vector"],item["evidence"],item["raw_tool_data"],item["reference_urls"]))
            db.execute("UPDATE scans SET state='completed',finished_at=CURRENT_TIMESTAMP,result_summary=? WHERE id=?", (f"{tool} completed with {len(records)} observations. Original output retained as import #{imported.lastrowid}.",scan_id))
        audit(scan["project_id"],"tool_scan.completed",f"scan_id={scan_id};tool={tool};observations={len(records)}")
    except Exception as exc:
        _finish_failed(scan_id,scan["project_id"],str(exc))
