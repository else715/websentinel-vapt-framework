import ipaddress
import json
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from fastapi import HTTPException


MAX_TOOL_OUTPUT = 2_000_000


def _run(argv: list[str], *, input_text: str = "", timeout: int) -> str:
    if not shutil.which(argv[0]):
        raise RuntimeError(f"{argv[0]} is not installed or is not available on PATH.")
    try:
        result = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{argv[0]} exceeded the {timeout}-second time limit.") from exc
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_TOOL_OUTPUT:
        raise RuntimeError(f"{argv[0]} output exceeded the 2 MB limit.")
    if result.returncode != 0:
        message = result.stderr.strip()[:500] or f"{argv[0]} exited with status {result.returncode}."
        raise RuntimeError(message)
    return result.stdout


def _valid_domain(hostname: str) -> str | None:
    value = hostname.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    if len(value) > 253 or re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value) is None:
        return None
    return value


def enumerate_subdomains(root_domain: str) -> tuple[list[str], str]:
    root = _valid_domain(root_domain)
    if root is None:
        raise HTTPException(400, "Subfinder requires a registered domain target.")
    output = _run(["subfinder", "-d", root, "-silent", "-nc", "-max-time", "5"], timeout=330)
    candidates = set()
    for line in output.splitlines():
        candidate = _valid_domain(line)
        if candidate and candidate != root and candidate.endswith("." + root):
            candidates.add(candidate)
            if len(candidates) >= 200:
                break
    return sorted(candidates), output


def probe_approved_hosts(hosts: list[str]) -> tuple[list[dict], str]:
    if not hosts:
        return [], ""
    if len(hosts) > 50:
        raise RuntimeError("The HTTP inventory is limited to 50 approved hosts per run.")
    normalized = []
    for host in hosts:
        value = _valid_domain(host)
        if value is None:
            try:
                value = str(ipaddress.ip_address(host))
            except ValueError as exc:
                raise RuntimeError("An approved target has an invalid hostname or IP address.") from exc
        normalized.append(value)
    argv = [
        "httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect",
        "-threads", "2", "-rate-limit", "5", "-timeout", "8", "-retries", "0",
        "-exclude", "private-ips", "-response-size-to-read", "100000",
    ]
    output = _run(argv, input_text="\n".join(normalized) + "\n", timeout=300)
    results = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"httpx returned invalid JSON on line {line_number}.") from exc
        if not isinstance(record, dict):
            continue
        host_value = str(record.get("input") or record.get("host") or "")
        parsed_host = urlsplit(host_value if "://" in host_value else "//" + host_value).hostname or host_value
        host = _valid_domain(parsed_host)
        if host is None:
            try:
                host = str(ipaddress.ip_address(parsed_host))
            except ValueError:
                continue
        if host not in normalized:
            continue
        tech = record.get("tech") or record.get("technologies") or []
        if not isinstance(tech, list):
            tech = [str(tech)]
        results.append({
            "host": host,
            "url": str(record.get("url") or "")[:1000],
            "status_code": str(record.get("status_code") or "")[:20],
            "title": str(record.get("title") or "")[:500],
            "technologies": [str(value)[:100] for value in tech[:50]],
            "raw": json.dumps(record, ensure_ascii=False)[:20000],
        })
    return results, output
