"""Bounded CLI adapters for the remaining assessment tools.

These functions accept only targets already approved by the caller. They never
construct shell commands and retain the tool's native output for provenance.
"""

import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


OUTPUT_LIMIT = 5_000_000


class ToolUnavailable(RuntimeError):
    pass


def _run(argv: list[str], *, timeout: int, stdin: str = "") -> str:
    if not shutil.which(argv[0]):
        raise ToolUnavailable(f"{argv[0]} is not installed or is not available on PATH.")
    result = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                           timeout=timeout, check=False, shell=False)
    output = result.stdout
    if len(output.encode("utf-8", errors="replace")) > OUTPUT_LIMIT:
        raise RuntimeError(f"{argv[0]} output exceeded the {OUTPUT_LIMIT}-byte limit.")
    if result.returncode:
        raise RuntimeError((result.stderr or f"{argv[0]} exited with status {result.returncode}.")[:500])
    return output


def run_nmap_inventory(approved_ip: str) -> str:
    """Conservative TCP service inventory; caller must pass a registered IP."""
    if not shutil.which("nmap"):
        raise ToolUnavailable("nmap is not installed or is not available on PATH.")
    with tempfile.TemporaryDirectory(prefix="websentinel-nmap-") as tmp:
        xml_path = str(Path(tmp) / "scan.xml")
        result = subprocess.run(["nmap", "-sT", "-sV", "-T3", "--top-ports", "1000", "--host-timeout", "5m",
                                 "-oX", xml_path, approved_ip], capture_output=True, text=True,
                                timeout=330, check=False, shell=False)
        if result.returncode:
            raise RuntimeError((result.stderr or "nmap inventory failed.")[:500])
        return Path(xml_path).read_text(encoding="utf-8", errors="replace")


def parse_nmap_xml(xml_text: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("Nmap did not produce valid XML.") from exc
    records = []
    for host in root.findall("host"):
        address = next((node.get("addr", "") for node in host.findall("address")
                        if node.get("addrtype") in {"ipv4", "ipv6"}), "")
        hostnames = [n.get("name", "") for n in host.findall("hostnames/hostname")]
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            records.append({"address": address, "hostnames": hostnames,
                            "protocol": port.get("protocol", ""), "port": port.get("portid", ""),
                            "service": service.get("name", "") if service is not None else "",
                            "product": service.get("product", "") if service is not None else "",
                            "version": service.get("version", "") if service is not None else ""})
    return records


def run_katana_crawl(approved_url: str) -> str:
    return _run(["katana", "-u", approved_url, "-jsonl", "-silent", "-depth", "3",
                 "-max-url", "500", "-crawl-duration", "5m", "-rl", "5", "-concurrency", "2"], timeout=330)


def parse_jsonl(text: str, tool: str) -> list[dict]:
    results = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid {tool} JSONL at line {line_number}.") from exc
        if isinstance(obj, dict):
            results.append(obj)
    return results


def run_nuclei_scan(approved_url: str) -> str:
    return _run(["nuclei", "-u", approved_url, "-jsonl", "-silent", "-severity",
                 "info,low,medium,high,critical", "-rl", "5", "-c", "2", "-timeout", "5",
                 "-retries", "0", "-max-host-error", "5"], timeout=600)


def run_zap_baseline(approved_url: str) -> str:
    executable = "zap-baseline.py" if shutil.which("zap-baseline.py") else "zap-baseline"
    if not shutil.which(executable):
        raise ToolUnavailable("OWASP ZAP baseline script is not installed or is not available on PATH.")
    with tempfile.TemporaryDirectory(prefix="websentinel-zap-") as tmp:
        work_dir = Path(tmp)
        report_path = work_dir / "zap-report.json"
        # Official ZAP container scripts require report paths to live under
        # /zap/wrk. Bind that path to the scan's private temporary directory
        # in Docker; locally the baseline script accepts the direct path.
        docker_work = Path("/zap/wrk")
        if docker_work.is_dir():
            report_path = docker_work / f"{work_dir.name}-report.json"
        result = subprocess.run(
            [executable, "-t", approved_url, "-J", str(report_path), "-m", "5", "-T", "10"],
            capture_output=True, text=True, timeout=900, check=False, shell=False,
        )
        if len(result.stdout.encode("utf-8", errors="replace")) > OUTPUT_LIMIT:
            raise RuntimeError("ZAP output exceeded the output limit.")
        # ZAP baseline uses exit statuses 1 and 2 for findings and warnings;
        # those are valid reports, while 3 indicates an execution error.
        if result.returncode not in {0, 1, 2}:
            raise RuntimeError((result.stderr or result.stdout or "ZAP baseline scan failed.")[:500])
        if not report_path.is_file():
            raise RuntimeError("ZAP completed without producing its JSON report.")
        try:
            return report_path.read_text(encoding="utf-8", errors="replace")
        finally:
            if report_path.parent != work_dir:
                report_path.unlink(missing_ok=True)
