import html
import hashlib
import ipaddress
import json
import re
import shutil
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from app.database import audit, connect, initialize
from app.rag import answer_project_question, draft_finding_analysis, seed_mapping_documents
from app.scanners.importers import parse_output
from app.services.discovery_jobs import execute_httpx_scan, execute_subfinder_scan, execute_tool_scan


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize()
    with connect() as db:
        seed_mapping_documents(db)
    yield


app = FastAPI(
    title="WebSentinel",
    description="Local-first workspace for authorized web assessments",
    version="0.1.0",
    lifespan=lifespan,
)


def normalize_host(value: str) -> tuple[str, str]:
    host = value.strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(ch in host for ch in "/:@?#\\"):
        raise HTTPException(400, "Enter a hostname or IP address, without a URL or port.")
    try:
        address = ipaddress.ip_address(host)
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise HTTPException(400, "Loopback, link-local, multicast, and unspecified IPs cannot be registered.")
        return str(address), "ip"
    except ValueError:
        if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host) is None:
            raise HTTPException(400, "Enter a valid fully qualified domain name or IP address.")
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
            raise HTTPException(400, "Local-only hostnames cannot be registered.")
        return host, "domain"


def page(title: str, content: str) -> str:
    rendered = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} · WebSentinel</title><style>
    :root{{color-scheme:dark;--bg:#10151c;--panel:#1a222d;--line:#2a3747;--text:#edf2f7;--muted:#a5b2c2;--accent:#67d5b5;--warn:#f4c56a}}
    *{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,sans-serif}}header{{padding:22px max(24px,calc((100vw - 1120px)/2));border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}}header strong{{font-size:20px;letter-spacing:.02em}}header span{{color:var(--muted);font-size:13px}}main{{max-width:1120px;margin:32px auto;padding:0 24px}}h1{{font-size:30px;margin:0 0 6px}}h2{{font-size:18px;margin:0 0 14px}}p{{color:var(--muted)}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}}.metric{{font-size:28px;font-weight:700;color:var(--accent)}}.metric-label{{color:var(--muted);font-size:13px}}.columns{{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}}label{{display:block;margin:10px 0 5px;color:var(--muted);font-size:13px}}input,textarea,select{{width:100%;background:#111820;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:10px;font:inherit}}textarea{{min-height:70px;resize:vertical}}button,.button{{display:inline-block;border:0;border-radius:7px;background:var(--accent);color:#0b1715;font-weight:700;padding:10px 14px;margin-top:12px;cursor:pointer;text-decoration:none}}.button.secondary{{background:#2b3948;color:var(--text)}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase}}small,.muted{{color:var(--muted)}}.notice{{padding:12px;border-left:3px solid var(--warn);background:#28241a;color:#ead7a8;border-radius:5px;margin:16px 0}}.error{{padding:12px;border-left:3px solid #ff7676;background:#301f24;border-radius:5px}}@media(max-width:760px){{.grid{{grid-template-columns:repeat(2,1fr)}}.columns{{grid-template-columns:1fr}}main{{margin-top:20px}}}}
    </style></head><body><header><strong>◈ WebSentinel</strong><span>Authorized assessment workspace</span></header><main>{content}</main></body></html>"""
    return rendered.replace("</body>", ASSISTANT_WIDGET + "</body>")


ASSISTANT_WIDGET = r"""<style>
.penguin-launch{position:fixed;right:24px;bottom:24px;z-index:1000;width:66px;height:66px;border-radius:50%;border:2px solid #72dec1;background:#17212b;box-shadow:0 8px 30px #0009;cursor:pointer;padding:5px}.penguin-launch svg{width:100%;height:100%}.penguin-launch:hover{transform:translateY(-2px)}
.assistant-box{display:none;position:fixed;right:24px;bottom:102px;z-index:1000;width:min(390px,calc(100vw - 32px));height:min(560px,calc(100vh - 130px));background:#151d26;border:1px solid #344456;border-radius:16px;box-shadow:0 18px 60px #000b;overflow:hidden;flex-direction:column}.assistant-box.open{display:flex}.assistant-head{padding:13px 16px;background:#202b37;display:flex;align-items:center;justify-content:space-between}.assistant-head b{font-size:15px}.assistant-head small{display:block;color:#a5b2c2}.assistant-select{padding:10px 12px;border-bottom:1px solid #2a3747}.assistant-select select{margin:0}.assistant-msgs{padding:12px;overflow:auto;flex:1}.assistant-msg{white-space:pre-wrap;padding:10px 12px;border-radius:12px;margin:8px 0;max-width:92%;font-size:14px}.assistant-msg.user{background:#21483f;margin-left:auto}.assistant-msg.bot{background:#222e3a}.assistant-msg a{color:#75e1c2}.assistant-status{color:#a5b2c2;font-size:12px;padding:0 12px}.assistant-compose{padding:10px;border-top:1px solid #2a3747;display:flex;gap:8px;align-items:end}.assistant-compose textarea{min-height:46px;max-height:100px;resize:vertical;margin:0}.assistant-compose button{margin:0;white-space:nowrap}.assistant-penguin{width:28px;height:28px;vertical-align:middle;margin-right:6px}
</style><button class="penguin-launch" id="penguin-launch" title="Chat with WebSentinel" aria-label="Open WebSentinel assistant"><svg viewBox="0 0 100 100" role="img" aria-label="Penguin avatar"><ellipse cx="50" cy="53" rx="34" ry="40" fill="#f4f7f8"/><ellipse cx="50" cy="51" rx="24" ry="33" fill="#18222c"/><ellipse cx="39" cy="42" rx="6" ry="8" fill="white"/><ellipse cx="61" cy="42" rx="6" ry="8" fill="white"/><circle cx="40" cy="43" r="2.5" fill="#10151c"/><circle cx="60" cy="43" r="2.5" fill="#10151c"/><path d="M43 53 L57 53 L50 61 Z" fill="#f1ad4e"/><ellipse cx="25" cy="84" rx="13" ry="6" fill="#efaa48"/><ellipse cx="75" cy="84" rx="13" ry="6" fill="#efaa48"/></svg></button><section class="assistant-box" id="assistant-box" aria-label="WebSentinel chat assistant"><div class="assistant-head"><div><b><svg class="assistant-penguin" viewBox="0 0 100 100"><ellipse cx="50" cy="53" rx="34" ry="40" fill="#f4f7f8"/><ellipse cx="50" cy="51" rx="24" ry="33" fill="#18222c"/><circle cx="40" cy="43" r="3" fill="white"/><circle cx="60" cy="43" r="3" fill="white"/><path d="M43 53 L57 53 L50 61 Z" fill="#f1ad4e"/></svg>WebSentinel assistant</b><small>Project records · knowledge base · Google search</small></div><button id="assistant-close" class="button secondary" type="button">×</button></div><div class="assistant-select"><select id="assistant-project" aria-label="Project context"><option value="">Choose project…</option></select></div><div class="assistant-msgs" id="assistant-msgs"><div class="assistant-msg bot">Ask about findings, PoCs, remediation, OWASP mappings, or assessment scope.</div></div><div class="assistant-status" id="assistant-status"></div><form class="assistant-compose" id="assistant-form"><textarea id="assistant-question" maxlength="3000" placeholder="Ask a question…" required></textarea><button type="submit">Send</button></form></section><script>
</script>"""


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "discovery_tools": {"subfinder": bool(shutil.which("subfinder")), "httpx": bool(shutil.which("httpx"))},
        "vulnerability_scanners": "import_only",
    }


@app.get("/api/projects")
def api_projects():
    with connect() as db:
        projects = db.execute("SELECT id,name FROM projects ORDER BY id DESC").fetchall()
    return {"projects": [dict(project) for project in projects]}


@app.get("/api/assistant/chat")
def assistant_history(project_id: int):
    with connect() as db:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise HTTPException(404, "Project not found.")
        messages = db.execute("SELECT role,content,sources FROM assistant_messages WHERE project_id=? ORDER BY id DESC LIMIT 30", (project_id,)).fetchall()
    return {"messages": [{"role": row["role"], "content": row["content"], "sources": json.loads(row["sources"] or "[]")} for row in reversed(messages)]}


@app.post("/api/assistant/chat")
async def assistant_chat(request: Request):
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(400, "Request body must be JSON.") from exc
    question = str(payload.get("question", "")).strip()[:3000]
    try:
        project_id = int(payload.get("project_id"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Choose a project for the assistant context.") from exc
    if not question:
        raise HTTPException(400, "Enter a question.")
    with connect() as db:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise HTTPException(404, "Project not found.")
        findings = db.execute("SELECT f.* FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.project_id=? ORDER BY f.id DESC LIMIT 30", (project_id,)).fetchall()
        history = list(reversed(db.execute("SELECT role,content FROM assistant_messages WHERE project_id=? ORDER BY id DESC LIMIT 8", (project_id,)).fetchall()))
        reply = answer_project_question(db, question, history, [dict(row) for row in findings])
        db.execute("INSERT INTO assistant_messages(project_id,role,content) VALUES (?,'user',?)", (project_id, question))
        db.execute("INSERT INTO assistant_messages(project_id,role,content,sources) VALUES (?,'assistant',?,?)", (project_id, reply["answer"], json.dumps(reply["sources"], ensure_ascii=False)))
    audit(project_id, "assistant.exchange", f"model={reply['model']};sources={len(reply['sources'])}")
    return {"answer": reply["answer"], "sources": reply["sources"]}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    with connect() as db:
        projects = db.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
        targets = db.execute("SELECT COUNT(*) FROM targets WHERE in_scope=1").fetchone()[0]
        scans = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        recent = db.execute("SELECT s.*, t.host FROM scans s JOIN targets t ON t.id=s.target_id ORDER BY s.id DESC LIMIT 8").fetchall()
    project_rows = "".join(
        f"<tr><td>{html.escape(row['name'])}</td><td>{html.escape(row['description'] or '—')}</td><td><a href='/projects/{row['id']}'>Open</a></td></tr>"
        for row in projects
    ) or "<tr><td colspan='3' class='muted'>No projects yet. Create one to begin.</td></tr>"
    scan_rows = "".join(
        f"<tr><td>#{row['id']}</td><td>{html.escape(row['host'])}</td><td>{html.escape(row['scan_type'])}</td><td>{html.escape(row['state'])}</td></tr>"
        for row in recent
    ) or "<tr><td colspan='4' class='muted'>No scan jobs yet.</td></tr>"
    content = f"""<h1>Assessment dashboard</h1><p>Track authorized scope, assessment jobs, and reviewed results.</p>
    <div class='notice'>Subfinder passive discovery and bounded httpx inventory are available. Vulnerability scanner execution remains disabled; import scanner output to review findings.</div>
    <section class='grid'><div class='card'><div class='metric'>{len(projects)}</div><div class='metric-label'>Projects</div></div><div class='card'><div class='metric'>{targets}</div><div class='metric-label'>In-scope targets</div></div><div class='card'><div class='metric'>{scans}</div><div class='metric-label'>Scan jobs</div></div><div class='card'><div class='metric'>{findings}</div><div class='metric-label'>Findings</div></div></section>
    <div class='columns'><section class='panel'><h2>Projects</h2><table><thead><tr><th>Name</th><th>Description</th><th></th></tr></thead><tbody>{project_rows}</tbody></table></section>
    <section class='panel'><h2>Create project</h2><form method='post' action='/projects'><label>Project name</label><input name='name' maxlength='100' required><label>Description</label><textarea name='description' maxlength='500'></textarea><button>Create project</button></form></section></div>
    <section class='panel' style='margin-top:16px'><h2>Recent scan jobs</h2><table><thead><tr><th>Job</th><th>Target</th><th>Type</th><th>State</th></tr></thead><tbody>{scan_rows}</tbody></table></section>"""
    return page("Dashboard", content)


@app.post("/projects")
def create_project(name: str = Form(...), description: str = Form("")):
    clean_name = name.strip()
    if not clean_name or len(clean_name) > 100 or len(description) > 500:
        raise HTTPException(400, "Project name or description is invalid.")
    with connect() as db:
        cursor = db.execute("INSERT INTO projects(name, description) VALUES (?, ?)", (clean_name, description.strip()))
        project_id = cursor.lastrowid
    audit(project_id, "project.created", clean_name)
    return HTMLResponse("<meta http-equiv='refresh' content='0;url=/'><p>Project created. <a href='/'>Continue</a></p>", status_code=201)


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(project_id: int):
    with connect() as db:
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if project is None:
            raise HTTPException(404, "Project not found.")
        targets = db.execute("SELECT * FROM targets WHERE project_id=? ORDER BY id DESC", (project_id,)).fetchall()
        assets = db.execute("SELECT a.*, rt.host AS root_host FROM assets a JOIN targets rt ON rt.id=a.root_target_id WHERE a.project_id=? ORDER BY CASE a.state WHEN 'candidate' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, a.hostname", (project_id,)).fetchall()
        scans = db.execute("SELECT s.*, t.host FROM scans s JOIN targets t ON t.id=s.target_id WHERE s.project_id=? ORDER BY s.id DESC", (project_id,)).fetchall()
        finding_counts = db.execute("SELECT f.severity, COUNT(*) AS n FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.project_id=? GROUP BY f.severity", (project_id,)).fetchall()
    target_rows = "".join(
        f"<tr><td>{html.escape(t['host'])}</td><td>{t['kind']}</td><td>{'In scope' if t['in_scope'] else 'Out of scope'}</td><td><form method='post' action='/projects/{project_id}/tools/run'><input type='hidden' name='target_id' value='{t['id']}'><select name='tool'><option value='nmap' {'disabled' if t['kind'] != 'ip' else ''}>Nmap</option><option value='katana'>Katana</option><option value='nuclei'>Nuclei</option><option value='zap'>ZAP baseline</option></select><label><input style='width:auto' type='checkbox' name='authorized' value='yes' required> I authorize this scan for this target.</label><button>Run tool</button></form></td></tr>"
        for t in targets
    ) or "<tr><td colspan='4' class='muted'>Register an authorized host to add it to scope.</td></tr>"
    asset_row_list = []
    for asset in assets:
        technologies = ", ".join(json.loads(asset["technologies"] or "[]"))
        controls = ""
        if asset["state"] == "candidate":
            controls = f"<form method='post' action='/projects/{project_id}/assets/{asset['id']}/status'><label><input style='width:auto' type='checkbox' name='authorization_confirmed' value='yes' required> I reviewed this host and approve it for this assessment's scope.</label><input type='hidden' name='state' value='approved'><button>Approve scope</button></form><form method='post' action='/projects/{project_id}/assets/{asset['id']}/status'><input type='hidden' name='state' value='rejected'><button class='button secondary'>Reject candidate</button></form>"
        asset_row_list.append(
            f"<tr><td>{html.escape(asset['hostname'])}</td><td>{html.escape(asset['state'])}</td><td>{html.escape(asset['discovery_source'])}</td><td>{html.escape(asset['http_status'] or '—')}</td><td>{html.escape(asset['page_title'] or '—')}<br><small>{html.escape(technologies or '—')}</small></td><td>{controls}</td></tr>"
        )
    asset_rows = "".join(asset_row_list) or "<tr><td colspan='6' class='muted'>No discovered hosts yet. Run passive discovery against an authorized domain target.</td></tr>"
    scan_rows = "".join(f"<tr><td>#{s['id']}</td><td>{html.escape(s['host'])}</td><td>{html.escape(s['scan_type'])}</td><td>{html.escape(s['state'])}<br><small>{html.escape(s['error_summary'] or s['result_summary'])}</small></td><td><a href='/reports/scans/{s['id']}'>Report</a></td></tr>" for s in scans) or "<tr><td colspan='5' class='muted'>No jobs recorded.</td></tr>"
    severity_cards = "".join(f"<div class='card'><div class='metric'>{count['n']}</div><div class='metric-label'>{html.escape(count['severity'])}</div></div>" for count in finding_counts) or "<div class='card'><div class='metric'>0</div><div class='metric-label'>Findings</div></div>"
    candidate_count = sum(1 for asset in assets if asset['state'] == 'candidate')
    domain_targets = [target for target in targets if target["kind"] == "domain"]
    subfinder_ready = bool(shutil.which("subfinder"))
    httpx_ready = bool(shutil.which("httpx"))
    domain_options = "".join(
        "<option value='" + str(target["id"]) + "'>" + html.escape(target["host"]) + "</option>"
        for target in domain_targets
    )
    discovery_form = (
        f"<form method='post' action='/projects/{project_id}/discover'><label>Registered domain</label><select name='target_id'>{domain_options}</select><label><input style='width:auto' type='checkbox' name='authorization_confirmed' value='yes' required> I confirm passive discovery is authorized for this registered domain.</label><button>Run Subfinder</button></form>"
        if domain_targets else "<p class='muted'>Register an authorized domain target to enable Subfinder discovery.</p>"
    )
    content = f"""<p><a href='/'>← Dashboard</a></p><h1>{html.escape(project['name'])}</h1><p>{html.escape(project['description'] or 'No description')}</p><p><a class='button' href='/reports/projects/{project_id}'>Project report</a> <a class='button secondary' href='/projects/{project_id}/assistant'>Ask WebSentinel</a></p><section class='grid'>{severity_cards}<div class='card'><div class='metric'>{candidate_count}</div><div class='metric-label'>Discovered candidates</div></div></section><div class='columns'>
    <section class='panel'><h2>Authorized targets</h2><table><thead><tr><th>Host</th><th>Kind</th><th>Scope</th><th>New job</th></tr></thead><tbody>{target_rows}</tbody></table></section>
    <section class='panel'><h2>Register target</h2><form method='post' action='/projects/{project_id}/targets'><label>Hostname or IP (no URL or port)</label><input name='host' placeholder='app.example.org' required><label><input style='width:auto' type='checkbox' name='authorized' value='yes' required> I am authorized to assess this target and have approval for this project.</label><button>Register in scope</button></form><p class='muted'>Only the registered host is approved. Discovered hosts do not enter scope automatically.</p></section></div>
    <section class='panel' style='margin-top:16px'><h2>Discovery</h2><p>Subfinder: {'ready' if subfinder_ready else 'not installed on PATH'}. It performs passive domain enumeration. New hosts remain candidates until you approve each one into scope.</p>{discovery_form}<hr><p>httpx: {'ready' if httpx_ready else 'not installed on PATH'}. It sends bounded HTTP probes only to registered in-scope targets and excludes private IP destinations by default.</p><form method='post' action='/projects/{project_id}/probe-http'><label><input style='width:auto' type='checkbox' name='authorization_confirmed' value='yes' required> I authorize a low-rate HTTP inventory of all approved hosts in this project.</label><button>Run httpx inventory</button></form></section>
    <section class='panel' style='margin-top:16px'><h2>Discovered assets and probe results</h2><table><thead><tr><th>Host</th><th>Scope status</th><th>Source</th><th>HTTP status</th><th>Title / technology</th><th>Scope review</th></tr></thead><tbody>{asset_rows}</tbody></table></section>
    <section class='panel' style='margin-top:16px'><h2>Assessment history</h2><table><thead><tr><th>Job</th><th>Target</th><th>Type</th><th>State / result</th><th></th></tr></thead><tbody>{scan_rows}</tbody></table></section>"""
    return page(project["name"], content)


@app.get("/projects/{project_id}/assistant", response_class=HTMLResponse)
def project_assistant(project_id: int):
    with connect() as db:
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if project is None:
            raise HTTPException(404, "Project not found.")
        messages = db.execute("SELECT * FROM assistant_messages WHERE project_id=? ORDER BY id", (project_id,)).fetchall()
    message_blocks = []
    for message in messages:
        content_text = "<br>".join(html.escape(line) for line in message["content"].splitlines())
        sources = json.loads(message["sources"] or "[]")
        source_links = " · ".join(
            f"<a href='{html.escape(source['url'], quote=True)}'>{html.escape(source['id'])}</a>" if source.get("url") else html.escape(source["id"])
            for source in sources
        )
        message_blocks.append(f"<article class='panel' style='margin:12px 0'><strong>{'You' if message['role']=='user' else 'WebSentinel'}</strong><p>{content_text}</p><small>{source_links}</small></article>")
    history_html = "".join(message_blocks) or "<p class='muted'>Ask about findings, evidence, remediation, OWASP mappings, or assessment scope.</p>"
    content = f"<p><a href='/projects/{project_id}'>← {html.escape(project['name'])}</a></p><h1>WebSentinel assistant</h1><div class='notice'>Answers use this project's records and the local reference pack. Replies are drafts, not validation; scanner output is treated as untrusted text.</div>{history_html}<section class='panel'><form method='post' action='/projects/{project_id}/assistant'><label>Your question</label><textarea name='question' maxlength='3000' required placeholder='Summarize the confirmed findings and suggest remediation priorities'></textarea><button>Ask</button></form><form method='post' action='/projects/{project_id}/assistant/clear'><button class='button secondary'>Clear conversation</button></form></section>"
    return page("Project assistant", content)


@app.post("/projects/{project_id}/assistant")
def ask_project_assistant(project_id: int, question: str = Form(...)):
    question = question.strip()
    if not question or len(question) > 3000:
        raise HTTPException(400, "Question must be 1–3000 characters.")
    with connect() as db:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise HTTPException(404, "Project not found.")
        findings = db.execute("SELECT f.* FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.project_id=? ORDER BY f.id DESC LIMIT 30", (project_id,)).fetchall()
        history = list(reversed(db.execute("SELECT role,content FROM assistant_messages WHERE project_id=? ORDER BY id DESC LIMIT 8", (project_id,)).fetchall()))
        reply = answer_project_question(db, question, history, [dict(row) for row in findings])
        db.execute("INSERT INTO assistant_messages(project_id,role,content) VALUES (?,'user',?)", (project_id, question))
        db.execute("INSERT INTO assistant_messages(project_id,role,content,sources) VALUES (?,'assistant',?,?)", (project_id, reply["answer"], json.dumps(reply["sources"], ensure_ascii=False)))
    audit(project_id, "assistant.exchange", f"model={reply['model']};sources={len(reply['sources'])}")
    return RedirectResponse(f"/projects/{project_id}/assistant", status_code=303)


@app.post("/projects/{project_id}/assistant/clear")
def clear_project_assistant(project_id: int):
    with connect() as db:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise HTTPException(404, "Project not found.")
        db.execute("DELETE FROM assistant_messages WHERE project_id=?", (project_id,))
    audit(project_id, "assistant.cleared")
    return RedirectResponse(f"/projects/{project_id}/assistant", status_code=303)


@app.post("/projects/{project_id}/targets")
def create_target(project_id: int, host: str = Form(...), authorized: str = Form("")):
    if authorized != "yes":
        raise HTTPException(400, "Authorization acknowledgment is required.")
    canonical, kind = normalize_host(host)
    with connect() as db:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise HTTPException(404, "Project not found.")
        try:
            cursor = db.execute("INSERT INTO targets(project_id, host, kind, authorization_acknowledged) VALUES (?, ?, ?, 1)", (project_id, canonical, kind))
            target_id = cursor.lastrowid
            db.execute(
                "INSERT INTO assets(project_id, root_target_id, target_id, hostname, state, discovery_source) VALUES (?, ?, ?, ?, 'approved', 'manual')",
                (project_id, target_id, target_id, canonical),
            )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(409, "This host is already registered in the project.") from exc
            raise
    audit(project_id, "target.registered", canonical)
    return HTMLResponse(f"<meta http-equiv='refresh' content='0;url=/projects/{project_id}'><p>Target registered. <a href='/projects/{project_id}'>Continue</a></p>", status_code=201)


@app.post("/projects/{project_id}/tools/run")
def run_project_tool(project_id: int, background_tasks: BackgroundTasks, target_id: int = Form(...), tool: str = Form(...), authorized: str = Form("")):
    if authorized != "yes" or tool not in {"nmap", "katana", "nuclei", "zap"}:
        raise HTTPException(400, "Choose a supported tool and confirm authorization.")
    with connect() as db:
        target = db.execute("SELECT * FROM targets WHERE id=? AND project_id=? AND in_scope=1 AND authorization_acknowledged=1", (target_id, project_id)).fetchone()
        if target is None:
            raise HTTPException(403, "Target is not approved and in scope.")
        if tool == "nmap" and target["kind"] != "ip":
            raise HTTPException(400, "Nmap requires a registered IP target.")
        cursor = db.execute("INSERT INTO scans(project_id,target_id,scan_type,state,options_summary) VALUES (?,?,?,'queued',?)", (project_id,target_id,tool,{"nmap":"Nmap service inventory: top 1000 TCP ports, version detection, 5-minute host timeout","katana":"Katana crawl: depth 3, 500 URL limit, 5-minute duration, 5 requests/second","nuclei":"Nuclei: approved target, conservative rate, no retries","zap":"OWASP ZAP baseline passive scan, 5-minute spider"}[tool]))
        scan_id = cursor.lastrowid
    audit(project_id,"tool_scan.queued",f"scan_id={scan_id};tool={tool};target={target['host']}")
    background_tasks.add_task(execute_tool_scan,scan_id,target_id,tool)
    return RedirectResponse(f"/projects/{project_id}",status_code=303)


@app.post("/projects/{project_id}/discover")
def start_subfinder_discovery(
    project_id: int,
    background_tasks: BackgroundTasks,
    target_id: int = Form(...),
    authorization_confirmed: str = Form(""),
):
    if authorization_confirmed != "yes":
        raise HTTPException(400, "Confirm authorization before running passive discovery.")
    with connect() as db:
        target = db.execute(
            "SELECT * FROM targets WHERE id=? AND project_id=? AND in_scope=1 AND authorization_acknowledged=1 AND kind='domain'",
            (target_id, project_id),
        ).fetchone()
        if target is None:
            raise HTTPException(403, "Select a registered, authorized domain target in this project.")
        cursor = db.execute(
            "INSERT INTO scans(project_id, target_id, scan_type, state, options_summary) VALUES (?, ?, 'passive_discovery', 'queued', 'Subfinder passive enumeration; max 5 minutes; no active target probing')",
            (project_id, target_id),
        )
        scan_id = cursor.lastrowid
    audit(project_id, "discovery.queued", f"scan_id={scan_id};tool=subfinder;target={target['host']}")
    background_tasks.add_task(execute_subfinder_scan, scan_id, target_id)
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@app.post("/projects/{project_id}/probe-http")
def start_httpx_inventory(
    project_id: int,
    background_tasks: BackgroundTasks,
    authorization_confirmed: str = Form(""),
):
    if authorization_confirmed != "yes":
        raise HTTPException(400, "Confirm authorization before starting HTTP inventory.")
    with connect() as db:
        targets = db.execute(
            "SELECT * FROM targets WHERE project_id=? AND in_scope=1 AND authorization_acknowledged=1 ORDER BY host LIMIT 51",
            (project_id,),
        ).fetchall()
        if not targets:
            raise HTTPException(400, "Register or approve at least one target before HTTP inventory.")
        if len(targets) > 50:
            raise HTTPException(400, "HTTP inventory is limited to 50 approved hosts per run.")
        cursor = db.execute(
            "INSERT INTO scans(project_id, target_id, scan_type, state, options_summary) VALUES (?, ?, 'http_inventory', 'queued', 'httpx: 2 threads, 5 requests/second, 8-second timeout, no retries, private IP destinations excluded')",
            (project_id, targets[0]["id"]),
        )
        scan_id = cursor.lastrowid
    audit(project_id, "discovery.queued", f"scan_id={scan_id};tool=httpx;approved_hosts={len(targets)}")
    background_tasks.add_task(execute_httpx_scan, scan_id, project_id)
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@app.post("/projects/{project_id}/assets/{asset_id}/status")
def review_discovered_asset(
    project_id: int,
    asset_id: int,
    state: str = Form(...),
    authorization_confirmed: str = Form(""),
):
    if state not in {"approved", "rejected"}:
        raise HTTPException(400, "Invalid asset review status.")
    with connect() as db:
        asset = db.execute(
            "SELECT a.*, root.host AS root_host, root.in_scope AS root_in_scope, root.authorization_acknowledged AS root_authorized FROM assets a JOIN targets root ON root.id=a.root_target_id WHERE a.id=? AND a.project_id=?",
            (asset_id, project_id),
        ).fetchone()
        if asset is None:
            raise HTTPException(404, "Discovered asset not found.")
        if asset["state"] != "candidate":
            raise HTTPException(409, "Only candidate assets can be reviewed this way.")
        if state == "approved":
            if authorization_confirmed != "yes":
                raise HTTPException(400, "Confirm that this host is authorized and in scope before approval.")
            if not asset["root_in_scope"] or not asset["root_authorized"]:
                raise HTTPException(403, "The root target is no longer authorized and in scope.")
            if not asset["hostname"].endswith("." + asset["root_host"]):
                raise HTTPException(403, "Discovered host is outside the registered root domain.")
            target = db.execute(
                "SELECT id FROM targets WHERE project_id=? AND host=?",
                (project_id, asset["hostname"]),
            ).fetchone()
            if target is None:
                cursor = db.execute(
                    "INSERT INTO targets(project_id, host, kind, authorization_acknowledged) VALUES (?, ?, 'domain', 1)",
                    (project_id, asset["hostname"]),
                )
                target_id = cursor.lastrowid
            else:
                target_id = target["id"]
            db.execute(
                "UPDATE assets SET state='approved', target_id=? WHERE id=?",
                (target_id, asset_id),
            )
        else:
            db.execute("UPDATE assets SET state='rejected' WHERE id=?", (asset_id,))
    audit(project_id, "asset.reviewed", f"asset_id={asset_id};host={asset['hostname']};state={state}")
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@app.post("/scans")
def create_scan(project_id: int = Form(...), target_id: int = Form(...), scan_type: str = Form(...)):
    allowed = {"inventory", "vulnerability_scan"}
    if scan_type not in allowed:
        raise HTTPException(400, "Unknown job type.")
    with connect() as db:
        target = db.execute("SELECT * FROM targets WHERE id=? AND project_id=?", (target_id, project_id)).fetchone()
        if target is None or not target["in_scope"] or not target["authorization_acknowledged"]:
            raise HTTPException(403, "Target is not authorized and in scope for this project.")
        cur = db.execute("INSERT INTO scans(project_id, target_id, scan_type, state, options_summary) VALUES (?, ?, ?, 'planned', 'Execution disabled in this build')", (project_id, target_id, scan_type))
        scan_id = cur.lastrowid
    audit(project_id, "scan_job.created", f"scan_id={scan_id};target={target['host']};type={scan_type}")
    return RedirectResponse(f"/reports/scans/{scan_id}", status_code=303)


@app.get("/reports/scans/{scan_id}", response_class=HTMLResponse)
def scan_report(scan_id: int):
    with connect() as db:
        scan = db.execute("SELECT s.*, p.name AS project_name, t.host FROM scans s JOIN projects p ON p.id=s.project_id JOIN targets t ON t.id=s.target_id WHERE s.id=?", (scan_id,)).fetchone()
        if scan is None:
            raise HTTPException(404, "Scan job not found.")
        findings = db.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        imports = db.execute("SELECT id, tool, filename, imported_at FROM scanner_imports WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
    finding_statuses = ("unreviewed", "confirmed", "false_positive", "accepted", "remediated", "retest_needed")
    finding_row_list = []
    for finding in findings:
        status_options = "".join(
            f"<option {'selected' if finding['status'] == status else ''}>{status}</option>"
            for status in finding_statuses
        )
        analysis = json.loads(finding["rag_analysis"] or "{}")
        owasp = json.loads(finding["owasp_mapping"] or "[]")
        mitre = json.loads(finding["mitre_mapping"] or "[]")
        mapping_items = [f"{item.get('id', '')} ({item.get('confidence', 'unrated')}): {item.get('rationale', '')}" for item in owasp + mitre]
        mapping_html = "<br>".join(html.escape(item) for item in mapping_items) or "<span class='muted'>No mapping draft</span>"
        analysis_html = "<br>".join(
            html.escape(value) for value in (
                analysis.get("summary", ""),
                f"Impact: {analysis.get('impact', '')}" if analysis.get("impact") else "",
                f"Draft remediation: {analysis.get('remediation', '')}" if analysis.get("remediation") else "",
            ) if value
        )
        sources_html = "<br>".join(f"<a href='{html.escape(item['url'], quote=True)}'>{html.escape(item['id'])}</a>" for item in analysis.get("retrieved_sources", []))
        raw_evidence_link = f"<br><a href='/imports/{finding['scanner_import_id']}/download'>Original scanner output</a>" if finding["scanner_import_id"] else ""
        finding_row_list.append(
            f"<tr><td><strong>{html.escape(finding['title'])}</strong><br><small>{html.escape(finding['source'])} · {html.escape(finding['asset'])}</small>{raw_evidence_link}</td><td>{html.escape(finding['severity'])}<br><small>CVSS: {html.escape(finding['cvss_score'] or '—')} {html.escape(finding['cvss_vector'])}</small></td><td>{html.escape(finding['status'])}</td><td>{html.escape(finding['description'])}<br><small>{html.escape(finding['evidence'])}<br>CWE: {html.escape(finding['cwe'] or '—')}</small></td><td>{html.escape(finding['remediation'])}<br><small>{analysis_html}</small></td><td>{mapping_html}<br><small>{sources_html}</small></td><td><form method='post' action='/findings/{finding['id']}/status'><select name='status'>{status_options}</select><button>Save</button></form></td></tr>"
        )
    rows = "".join(finding_row_list) or "<tr><td colspan='7' class='muted'>No findings recorded yet.</td></tr>"
    states = ("planned", "running", "failed", "in_review", "completed", "cancelled")
    state_options = "".join(f"<option value='{state}' {'selected' if scan['state'] == state else ''} {'disabled' if state in {'running', 'failed'} else ''}>{state.replace('_', ' ').title()}</option>" for state in states)
    import_rows = "".join(
        f"<li>{html.escape(imported['tool'])} · {html.escape(imported['filename']) or 'output'} · {html.escape(imported['imported_at'])} — <a href='/imports/{imported['id']}/download'>download original</a></li>"
        for imported in imports
    ) or "<li class='muted'>No imported tool output yet.</li>"
    scan_message = scan["error_summary"] or scan["result_summary"]
    scan_notice = "Subfinder and httpx jobs execute the bounded discovery profiles shown in the project. Vulnerability scanner execution is not enabled. Imported alerts and AI mappings are drafts, not confirmed vulnerabilities. MITRE ATT&CK describes observed adversary behavior; vulnerability presence alone is not ATT&CK evidence."
    content = f"<h1>Assessment job #{scan['id']}</h1><p>Project: {html.escape(scan['project_name'])} · Target: {html.escape(scan['host'])}</p><p>Type: {html.escape(scan['scan_type'])} · State: {html.escape(scan['state'])} · Created: {html.escape(scan['created_at'])}</p><div class='notice'>{html.escape(scan_notice)}<br>{html.escape(scan_message)}</div><section class='panel'><h2>Assessment status</h2><form method='post' action='/scans/{scan_id}/state'><select name='state'>{state_options}</select><button>Update status</button></form></section><section class='panel' style='margin-top:16px'><h2>Imported output evidence</h2><ul>{import_rows}</ul></section><section class='panel' style='margin-top:16px'><h2>Import scanner output</h2><p>Supported: Nuclei JSONL and OWASP ZAP JSON. Original file content is retained as evidence.</p><form method='post' enctype='multipart/form-data' action='/scans/{scan_id}/imports'><label>Tool</label><select name='tool'><option value='nuclei'>Nuclei JSONL</option><option value='zap'>OWASP ZAP JSON</option></select><label>Output file (max 2 MB)</label><input type='file' name='output_file' required><button>Import findings</button></form><form method='post' action='/scans/{scan_id}/analyze'><button>Draft RAG report analysis for findings</button></form><p class='muted'>Analysis uses local Ollama. Scanner text is treated as untrusted input; generated mappings stay unreviewed until a human validates them.</p></section><section class='panel' style='margin-top:16px'><h2>Findings</h2><table><thead><tr><th>Finding / asset</th><th>Severity</th><th>Status</th><th>Description / evidence</th><th>Remediation / draft</th><th>Mappings / references</th><th>Review</th></tr></thead><tbody>{rows}</tbody></table></section><section class='panel' style='margin-top:16px'><h2>Add finding</h2><form method='post' action='/scans/{scan_id}/findings'><label>Title</label><input name='title' maxlength='200' required><label>Affected asset or URL</label><input name='asset' maxlength='500'><label>Severity</label><select name='severity'>{''.join(f'<option>{v}</option>' for v in ('Informational', 'Low', 'Medium', 'High', 'Critical'))}</select><label>Description / evidence summary</label><textarea name='description' maxlength='4000'></textarea><label>Remediation</label><textarea name='remediation' maxlength='4000'></textarea><label>Source (manual, tool name, or rule ID)</label><input name='source' maxlength='200' value='Manual review'><button>Save as unreviewed</button></form></section><p><a class='button secondary' href='/projects/{scan['project_id']}'>Back to project</a> <a class='button' href='/reports/scans/{scan_id}/download'>Download HTML</a></p>"
    return page("Assessment report", content)


@app.get("/reports/scans/{scan_id}/download", response_class=HTMLResponse)
def download_scan_report(scan_id: int):
    body = scan_report(scan_id)
    return HTMLResponse(body, headers={"Content-Disposition": f'attachment; filename="websentinel-scan-{scan_id}.html"'})


@app.get("/imports/{import_id}/download", response_class=PlainTextResponse)
def download_import(import_id: int):
    with connect() as db:
        imported = db.execute("SELECT raw_output FROM scanner_imports WHERE id=?", (import_id,)).fetchone()
    if imported is None:
        raise HTTPException(404, "Scanner output import not found.")
    return PlainTextResponse(
        imported["raw_output"],
        headers={"Content-Disposition": f'attachment; filename="websentinel-import-{import_id}.txt"'},
    )


@app.post("/scans/{scan_id}/findings")
def add_finding(
    scan_id: int,
    title: str = Form(...),
    asset: str = Form(""),
    severity: str = Form("Informational"),
    description: str = Form(""),
    remediation: str = Form(""),
    source: str = Form("Manual review"),
):
    title = title.strip()
    if not title or len(title) > 200 or len(asset) > 500 or len(description) > 4000 or len(remediation) > 4000 or len(source) > 200:
        raise HTTPException(400, "Finding fields exceed allowed lengths or title is empty.")
    if severity not in {"Informational", "Low", "Medium", "High", "Critical"}:
        raise HTTPException(400, "Invalid severity.")
    with connect() as db:
        scan = db.execute("SELECT project_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise HTTPException(404, "Scan job not found.")
        db.execute(
            "INSERT INTO findings(scan_id, title, asset, severity, description, remediation, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, title, asset.strip(), severity, description.strip(), remediation.strip(), source.strip()),
        )
    audit(scan["project_id"], "finding.created", f"scan_id={scan_id};severity={severity};status=unreviewed")
    return RedirectResponse(f"/reports/scans/{scan_id}", status_code=303)


@app.post("/scans/{scan_id}/imports")
async def import_scanner_output(
    scan_id: int,
    tool: str = Form(...),
    output_file: UploadFile = File(...),
):
    if tool not in {"nuclei", "zap"}:
        raise HTTPException(400, "Supported tools are Nuclei and OWASP ZAP.")
    raw = await output_file.read(2_000_001)
    if len(raw) > 2_000_000:
        raise HTTPException(413, "Scanner output exceeds the 2 MB import limit.")
    try:
        raw_text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "Scanner output must be UTF-8 text.") from exc
    findings = parse_output(tool, raw_text)
    digest = hashlib.sha256(raw).hexdigest()
    with connect() as db:
        scan = db.execute("SELECT project_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise HTTPException(404, "Assessment job not found.")
        try:
            cursor = db.execute(
                "INSERT INTO scanner_imports(scan_id, tool, filename, sha256, raw_output) VALUES (?, ?, ?, ?, ?)",
                (scan_id, tool, (output_file.filename or "")[:255], digest, raw_text),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "This exact output file was already imported for the assessment.") from exc
        import_id = cursor.lastrowid
        for finding in findings:
            db.execute(
                "INSERT INTO findings(scan_id, title, asset, severity, status, description, remediation, source, scanner_import_id, cwe, cvss_score, cvss_vector, evidence, raw_tool_data, reference_urls) VALUES (?, ?, ?, ?, 'unreviewed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, finding["title"], finding["asset"], finding["severity"], finding["description"], finding["remediation"], finding["source"], import_id, finding["cwe"], finding["cvss_score"], finding["cvss_vector"], finding["evidence"], finding["raw_tool_data"], finding["reference_urls"]),
            )
    audit(scan["project_id"], "scanner_output.imported", f"scan_id={scan_id};tool={tool};findings={len(findings)};sha256={digest}")
    return RedirectResponse(f"/reports/scans/{scan_id}", status_code=303)


@app.post("/scans/{scan_id}/analyze")
def analyze_scan_findings(scan_id: int):
    with connect() as db:
        scan = db.execute("SELECT project_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise HTTPException(404, "Assessment job not found.")
        findings = db.execute(
            "SELECT * FROM findings WHERE scan_id=? AND status IN ('unreviewed', 'confirmed') ORDER BY id LIMIT 10",
            (scan_id,),
        ).fetchall()
    for row in findings:
        finding = dict(row)
        with connect() as db:
            analysis = draft_finding_analysis(db, finding)
        owasp_json = json.dumps(analysis["owasp"], ensure_ascii=False)
        mitre_json = json.dumps(analysis["mitre_attack"], ensure_ascii=False)
        serialized = json.dumps(analysis, ensure_ascii=False)
        with connect() as db:
            db.execute(
                "UPDATE findings SET owasp_mapping=?, mitre_mapping=?, rag_analysis=? WHERE id=? AND status IN ('unreviewed', 'confirmed')",
                (owasp_json, mitre_json, serialized, row["id"]),
            )
    audit(scan["project_id"], "rag.analysis_drafted", f"scan_id={scan_id};findings={len(findings)};model=local-ollama")
    return RedirectResponse(f"/reports/scans/{scan_id}", status_code=303)


@app.post("/findings/{finding_id}/status")
def update_finding_status(finding_id: int, status: str = Form(...)):
    allowed = {"unreviewed", "confirmed", "false_positive", "accepted", "remediated", "retest_needed"}
    if status not in allowed:
        raise HTTPException(400, "Invalid finding status.")
    with connect() as db:
        row = db.execute("SELECT f.scan_id, s.project_id FROM findings f JOIN scans s ON s.id=f.scan_id WHERE f.id=?", (finding_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Finding not found.")
        db.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
    audit(row["project_id"], "finding.status_updated", f"finding_id={finding_id};status={status}")
    return RedirectResponse(f"/reports/scans/{row['scan_id']}", status_code=303)


@app.post("/scans/{scan_id}/state")
def update_scan_state(scan_id: int, state: str = Form(...)):
    allowed = {"planned", "in_review", "completed", "cancelled"}
    if state not in allowed:
        raise HTTPException(400, "Invalid assessment status.")
    with connect() as db:
        scan = db.execute("SELECT project_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise HTTPException(404, "Assessment job not found.")
        db.execute("UPDATE scans SET state=? WHERE id=?", (state, scan_id))
    audit(scan["project_id"], "assessment.status_updated", f"scan_id={scan_id};state={state}")
    return RedirectResponse(f"/reports/scans/{scan_id}", status_code=303)


@app.get("/reports/projects/{project_id}", response_class=HTMLResponse)
def project_report(project_id: int):
    with connect() as db:
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if project is None:
            raise HTTPException(404, "Project not found.")
        targets = db.execute("SELECT * FROM targets WHERE project_id=? ORDER BY host", (project_id,)).fetchall()
        assets = db.execute("SELECT hostname, state, discovery_source, http_status, page_title, technologies FROM assets WHERE project_id=? ORDER BY hostname", (project_id,)).fetchall()
        scans = db.execute("SELECT s.*, t.host FROM scans s JOIN targets t ON t.id=s.target_id WHERE s.project_id=? ORDER BY s.id", (project_id,)).fetchall()
        findings = db.execute("SELECT f.*, s.id AS assessment_id, t.host FROM findings f JOIN scans s ON s.id=f.scan_id JOIN targets t ON t.id=s.target_id WHERE s.project_id=? ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, f.id", (project_id,)).fetchall()
    target_rows = "".join(f"<li>{html.escape(t['host'])} ({t['kind']}, {'in scope' if t['in_scope'] else 'out of scope'})</li>" for t in targets) or "<li>No targets registered</li>"
    asset_rows = "".join(
        f"<tr><td>{html.escape(asset['hostname'])}</td><td>{html.escape(asset['state'])}</td><td>{html.escape(asset['discovery_source'])}</td><td>{html.escape(asset['http_status'] or '—')}</td><td>{html.escape(asset['page_title'] or '—')}<br><small>{html.escape(', '.join(json.loads(asset['technologies'] or '[]')) or '—')}</small></td></tr>"
        for asset in assets
    ) or "<tr><td colspan='5'>No discovered assets</td></tr>"
    scan_rows = "".join(f"<tr><td>#{s['id']}</td><td>{html.escape(s['host'])}</td><td>{html.escape(s['scan_type'])}</td><td>{html.escape(s['state'])}</td><td>{html.escape(s['created_at'])}</td></tr>" for s in scans) or "<tr><td colspan='5'>No assessments recorded</td></tr>"
    finding_row_list = []
    for finding in findings:
        owasp = json.loads(finding["owasp_mapping"] or "[]")
        mitre = json.loads(finding["mitre_mapping"] or "[]")
        mapping_text = "<br>".join(
            html.escape(f"{item.get('id', '')} ({item.get('confidence', 'unrated')}): {item.get('rationale', '')}")
            for item in owasp + mitre
        ) or "—"
        analysis = json.loads(finding["rag_analysis"] or "{}")
        draft = html.escape(analysis.get("summary", ""))
        if analysis.get("impact"):
            draft += "<br><small>Impact: " + html.escape(analysis["impact"]) + "</small>"
        if analysis.get("remediation"):
            draft += "<br><small>Draft remediation: " + html.escape(analysis["remediation"]) + "</small>"
        mapping_sources = "<br>".join(
            f"<a href='{html.escape(source['url'], quote=True)}'>{html.escape(source['id'])}</a>"
            for source in analysis.get("retrieved_sources", [])
        )
        if mapping_sources:
            mapping_text += "<br><small>Sources: " + mapping_sources + "</small>"
        raw_link = f"<br><a href='/imports/{finding['scanner_import_id']}/download'>Original scanner output</a>" if finding["scanner_import_id"] else ""
        finding_row_list.append(
            f"<tr><td>{html.escape(finding['title'])}<br><small>{html.escape(finding['source'])}</small>{raw_link}</td><td>{html.escape(finding['host'])}<br><small>{html.escape(finding['asset'])}</small></td><td>{html.escape(finding['severity'])}<br><small>CVSS: {html.escape(finding['cvss_score'] or '—')} {html.escape(finding['cvss_vector'])}</small></td><td>{html.escape(finding['status'])}</td><td>{html.escape(finding['description'])}<br><small>{html.escape(finding['evidence'])}<br>CWE: {html.escape(finding['cwe'] or '—')}</small></td><td>{html.escape(finding['remediation'])}<br><small>{draft}</small></td><td>{mapping_text}</td></tr>"
        )
    finding_rows = "".join(finding_row_list) or "<tr><td colspan='7'>No findings recorded</td></tr>"
    severity_summary = " · ".join(f"{sev}: {sum(1 for f in findings if f['severity'] == sev)}" for sev in ("Critical", "High", "Medium", "Low", "Informational"))
    content = f"<h1>Assessment report: {html.escape(project['name'])}</h1><p>{html.escape(project['description'] or '')}</p><p>Generated: {datetime.now().astimezone().isoformat(timespec='minutes')}</p><div class='notice'>This report reflects authorized target inventory, imported scanner output, and reviewer-entered records. Subfinder results remain candidate assets until approved. RAG analyses and OWASP mappings are drafts. MITRE ATT&CK describes adversary behavior, so vulnerability presence alone is not mapped as observed ATT&CK behavior.</div><section class='panel'><h2>Authorized scope</h2><ul>{target_rows}</ul></section><section class='panel' style='margin-top:16px'><h2>Discovered assets</h2><table><thead><tr><th>Host</th><th>Scope status</th><th>Source</th><th>HTTP status</th><th>Title / technology</th></tr></thead><tbody>{asset_rows}</tbody></table></section><section class='panel' style='margin-top:16px'><h2>Assessment history</h2><table><thead><tr><th>Job</th><th>Target</th><th>Type</th><th>Status</th><th>Created</th></tr></thead><tbody>{scan_rows}</tbody></table></section><section class='panel' style='margin-top:16px'><h2>Findings summary</h2><p>{html.escape(severity_summary)}</p><table><thead><tr><th>Finding / source</th><th>Asset</th><th>Severity</th><th>Status</th><th>Description / evidence</th><th>Remediation / draft</th><th>OWASP / ATT&CK suggestions</th></tr></thead><tbody>{finding_rows}</tbody></table></section><p><a class='button secondary' href='/projects/{project_id}'>Back to project</a> <a class='button' href='/reports/projects/{project_id}/download'>Download HTML</a></p>"
    return page("Project report", content)


@app.get("/reports/projects/{project_id}/download", response_class=HTMLResponse)
def download_project_report(project_id: int):
    body = project_report(project_id)
    return HTMLResponse(body, headers={"Content-Disposition": f'attachment; filename="websentinel-project-{project_id}.html"'})
