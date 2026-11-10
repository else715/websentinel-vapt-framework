import json

from fastapi import HTTPException


SEVERITIES = {"info": "Informational", "informational": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}


def _severity(value: str) -> str:
    return SEVERITIES.get(str(value or "info").strip().lower(), "Informational")


def parse_nuclei(text: str) -> list[dict]:
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"Invalid Nuclei JSONL at line {line_number}.") from exc
        if not isinstance(item, dict):
            raise HTTPException(400, f"Nuclei JSONL line {line_number} is not an object.")
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        classification = info.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        cwe_ids = classification.get("cwe-id", [])
        if isinstance(cwe_ids, (str, int)):
            cwe_ids = [cwe_ids]
        elif not isinstance(cwe_ids, list):
            cwe_ids = []
        findings.append({
            "title": str(info.get("name") or item.get("template-id") or "Nuclei finding")[:200],
            "asset": str(item.get("matched-at") or item.get("host") or item.get("url") or "")[:500],
            "severity": _severity(info.get("severity")),
            "description": str(info.get("description") or "")[:4000],
            "remediation": str(info.get("remediation") or "")[:4000],
            "source": f"Nuclei · {item.get('template-id', 'unknown template')}"[:200],
            "cwe": ", ".join(str(tag) for tag in cwe_ids if tag)[:500],
            "cvss_score": str(classification.get("cvss-score") or "")[:20],
            "cvss_vector": str(classification.get("cvss-metrics") or "")[:200],
            "evidence": str(item.get("matcher-name") or item.get("extracted-results") or "")[:4000],
            "reference_urls": json.dumps(references, ensure_ascii=False)[:4000],
            "raw_tool_data": json.dumps(item, ensure_ascii=False)[:20000],
        })
    return findings


def parse_zap(text: str) -> list[dict]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Invalid ZAP JSON report.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(400, "ZAP JSON report root must be an object.")
    alerts = payload.get("alerts") or []
    if isinstance(alerts, dict):
        alerts = [alerts]
    if not isinstance(alerts, list):
        alerts = []
    sites = payload.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_alerts = site.get("alerts") or []
        if isinstance(site_alerts, dict):
            site_alerts = [site_alerts]
        if isinstance(site_alerts, list):
            alerts.extend(site_alerts)
    findings = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        risk = str(alert.get("riskdesc") or alert.get("risk") or "Informational")
        cwe = alert.get("cweid") or alert.get("cwe") or ""
        refs = alert.get("reference") or alert.get("references") or ""
        if isinstance(refs, (dict, list)):
            refs = json.dumps(refs, ensure_ascii=False)
        evidence = alert.get("evidence") or alert.get("param") or ""
        findings.append({
            "title": str(alert.get("name") or alert.get("alert") or "ZAP alert")[:200],
            "asset": str(alert.get("url") or alert.get("uri") or "")[:500],
            "severity": _severity(risk.split()[0]),
            "description": str(alert.get("desc") or alert.get("description") or "")[:4000],
            "remediation": str(alert.get("solution") or alert.get("remediation") or "")[:4000],
            "source": f"OWASP ZAP · {alert.get('pluginid', alert.get('alertRef', 'alert'))}"[:200],
            "cwe": str(cwe)[:500],
            "cvss_score": str(alert.get("cvss_score") or alert.get("cvssScore") or "")[:20],
            "cvss_vector": str(alert.get("cvss_vector") or alert.get("cvssVector") or "")[:200],
            "evidence": str(evidence)[:4000],
            "reference_urls": str(refs)[:4000],
            "raw_tool_data": json.dumps(alert, ensure_ascii=False)[:20000],
        })
    return findings


def parse_output(tool: str, text: str) -> list[dict]:
    if tool == "nuclei":
        return parse_nuclei(text)
    if tool == "zap":
        return parse_zap(text)
    raise HTTPException(400, "Unsupported scanner output type.")
