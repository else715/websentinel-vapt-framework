# WebSentinel

WebSentinel is a local-first workspace for organizing authorized web application assessments. It provides project and target registration, scope acknowledgment, passive Subfinder discovery, candidate review, bounded httpx inventory, Nmap/Katana/Nuclei/ZAP scans, finding review, local RAG-assisted mapping drafts, severity summaries, and downloadable HTML reports.

## Run with Docker (recommended)

Install Docker Desktop (Windows or macOS) or Docker Engine with the Compose plugin (Linux), then run from this folder:

```sh
docker compose up --build
```

On first launch Docker builds the app image, installs the scanner CLIs, downloads the OWASP ZAP image contents and Nuclei templates, and pulls the configured Ollama model. The default model is about 5.2 GB and the full setup needs several additional GB for container images. Open <http://127.0.0.1:8000> when the app starts. The default setup runs inference on the CPU; 16 GB of system memory is recommended for the bundled 8B model.

For an NVIDIA GPU on a Docker host configured for GPU containers, use:

```sh
docker compose -f compose.yaml -f compose.gpu.yaml up --build
```

The app database, scanner configuration, and Ollama model weights persist in Docker volumes across restarts. Stop with `Ctrl+C`; use `docker compose down` to stop and remove containers. Do not use `docker compose down -v` unless you intend to erase all project records and downloaded model data. To choose another Ollama model, set `WEBSENTINEL_OLLAMA_MODEL` in a local `.env` file before starting Compose; the model is pulled automatically.

Docker needs internet access for the initial image, model, and scanner-template downloads. Refresh the Nuclei templates later with `docker compose exec app nuclei -update-templates`.

### Public web research in assistant chats

The assistant uses its local OWASP/ATT&CK knowledge base and project records by default. For questions about public PoCs or current remediation, it can also retrieve Google Programmable Search Engine results. Create a local `.env` from `.env.example`, then set `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_ID`. The assistant only searches when the question asks for a PoC, exploit reference, patch, fix, mitigation, advisory, or remediation. It sends a CVE ID or vulnerability title to Google, not scanner evidence or project assets. Search snippets are treated as untrusted and returned results are linked for review.

Google's Custom Search JSON API is currently limited to existing customers and is scheduled to stop on January 1, 2027. If you do not already have API access, the app continues using its local knowledge base and project data, and tells you when Google search could not run. See Google's [API status and migration options](https://developers.google.com/custom-search/v1/overview).

The web service is published on localhost only by default. Scanner jobs run inside the app container and can reach targets accessible from the Docker host's network. Use the application's authorization and scope controls, and scan only systems you are authorized to assess.

## Run locally

Python 3.11 or newer is recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. SQLite data is stored in `websentinel.db` in the working directory. Keep the server bound to localhost; this initial version has no user authentication.

## Current scope

- Create projects.
- Register a hostname or IP address after acknowledging authorization.
- Run passive Subfinder discovery for a registered domain covered by authorization. Discovered hosts remain candidates until individually approved into scope.
- Run low-rate httpx inventory against approved hosts only. The profile uses two threads, a 5 request/second cap, an 8-second timeout, no retries, and excludes private IP destinations.
- Launch Nmap on registered IP targets, Katana crawling, Nuclei scans, or ZAP baseline from each approved target row. Each job is recorded and the native output is retained; Nmap ports and Katana endpoints are normalized, while Nuclei/ZAP alerts enter the unreviewed finding workflow.
- Create assessment records for an in-scope target.
- Set assessments to planned, in review, completed, or cancelled.
- Add findings manually. New findings are unreviewed and can be marked confirmed, false positive, accepted, remediated, or retest-needed.
- Import Nuclei JSONL or OWASP ZAP JSON output. The original file is retained, duplicate files are rejected, and parsed findings start as unreviewed.
- Draft evidence-grounded OWASP Top 10:2025 mappings and remediation summaries with local Ollama. The mapping catalog is stored locally and searched using SQLite keyword retrieval.
- ATT&CK T1190 is conditional: it is omitted unless the finding is confirmed and its evidence explicitly records observed exploitation. A vulnerability alert alone is not ATT&CK behavior.
- Review assessment history and findings; download per-assessment or project HTML reports.

## Optional local RAG model (without Docker)

Install [Ollama](https://ollama.com/download), then pull a local model. Qwen3 8B is available under Apache 2.0 in the Ollama model catalog; check the license for any model you choose.

```powershell
ollama pull qwen3:8b
$env:WEBSENTINEL_OLLAMA_MODEL = "qwen3:8b"
$env:WEBSENTINEL_OLLAMA_URL = "http://127.0.0.1:11434"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

On an assessment page, import a Nuclei JSONL or ZAP JSON result, then choose **Draft RAG report analysis**. Ollama must be running locally. Without it, imports and report generation still work; the RAG action reports that the local model is unavailable.

Each project also has an **Ask WebSentinel** chat. It retrieves relevant mapping references and recent project findings, then sends that context and the last few turns to local Ollama. Answers include source IDs/links and do not change finding status.

The RAG request excludes raw scanner blobs and redacts common credential/token fields. Keep `WEBSENTINEL_OLLAMA_URL` pointed at a trusted local Ollama instance if assessment data must stay on the machine.

## Discovery tool installation (without Docker)

Subfinder, httpx, Nmap, Katana, Nuclei, and OWASP ZAP must be installed separately and available on `PATH` for their project-page actions when running without Docker. Follow each tool's official installation instructions. The Docker image bundles these tools. The app invokes fixed argument arrays and bounded profiles.

Run Subfinder only for a registered domain covered by your authorization. Review each candidate before approving it. Run httpx only after approving in-scope hosts; the app never passes unapproved candidates to it.

See [ROADMAP.md](ROADMAP.md) for the staged build plan and security requirements.
