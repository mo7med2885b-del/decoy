<p align="center"><img src="assets/logo.png" alt="Decoy logo" width="110"></p>

<h1 align="center">Decoy</h1>

**Open a suspicious link without risking your machine.** Paste a link; three AI visitors open it in **sealed, throwaway browsers on Vultr**, type **fake** passwords and card numbers, and watch where the data goes. **Ten AI agents on different open models** read the evidence and argue it out in a chat room chaired by an orchestrator until they vote. You get a plain verdict with proof, the country the stolen data would reach, a block-list and a PDF report. Then every sandbox is destroyed.

> **Live demo: https://45-32-155-174.sslip.io** (Vultr server, HTTPS, rate limited, daily budget cap). Test links are our own fake sites.

<p align="center"><img src="assets/screens/scan-live.jpg" alt="A live scan: three visitors in separate sandboxes and the agent chat room" width="100%"></p>

## What you get
- **Instant address read** (under a second): a transparent checklist of about 25 clues scores the link itself and gives three plain reasons, before any sandbox opens. A hint, never the verdict.
- **Sealed browsers** (Docker + gVisor, read-only, no root, no secrets, private networks blocked twice). The first picture appears in 2 to 4 seconds because clean sandboxes are kept warm; each is used once, then destroyed.
- **Three visitors** (laptop, phone, security bot) compare what they saw: a login form shown to people but a harmless page to the bot is cloaking. Bot checks are reported, never solved.
- **Agent swarm, every agent an AI model:** ten agents (DeepSeek, Qwen, MiMo, MiniMax and GLM through Vultr) read the facts code counted for their area and write what they mean. They post findings, **ask each other pointed questions**, and the orchestrator (`glm-5.3`) joins in, asks the agents directly, proposes a statement and calls the vote. Every agent votes with its own model; objections trigger another round. Code never writes a question or a reply: it only validates, counts the votes and owns the score. Click any agent to read its model and system prompt.
- **Where the data goes:** endpoint and country on a globe, a block-list (`.txt`, hosts file, JSON) and an abuse-report draft. Decoy never blocks or reports by itself.
- **Inspector and AI summary:** every request, cookie, script and console line, plus a plain-words summary (facts counted by code).
- **Normal or Advanced investigation:** Advanced adds the analyst team's incident report (indicators, suggested ATT&CK mapping). Every scan downloads as a **PDF with screenshots**.

<p align="center"><img src="assets/screens/chatroom.jpg" alt="The agent chat room" width="48%"> &nbsp; <img src="assets/screens/verdict.jpg" alt="Verdict" width="48%"></p>

## Honest by design
- **Needs a human look:** when the evidence conflicts (a bot check hid the page, or the address looks risky while the visit looked clean) Decoy says so instead of guessing.
- **Your decisions count:** *Block* and *Mark as safe* become real block and allow lists that win over the score, and the verdict says so.
- **Base rate:** most links are harmless, so every flag reminds you to read the reasons and screenshots first.
- **General judgment guide:** every agent is told what is normal on legitimate sites (trackers, newsletter forms, "sign in with ...", young domains) and what real warning signs look like, so big honest sites are not accused.

## Measured, not only claimed
The design follows published research: scam kits hide from scanners with user-agent, location and script checks (*PhishFarm*, IEEE S&P 2019), so three different visitors open every link; address features are long-studied signals (Marchal et al., ICDCS 2016, and the URL-feature literature); our addition is **behaviour in a sealed browser**.

**First measurement** (`tools/benchmark.py`, reproducible): on 50 fresh links, 62% of the phishing links Decoy could assess were flagged (95% interval 43% to 79%) and 3 of 17 well-known sites were wrongly flagged (interval 6% to 41%) *before* later false-alarm fixes. A re-measurement after the fixes is being run; this section will be replaced with its numbers.

## Run it
```bash
pip install -r requirements.txt
python -m playwright install chromium
docker build -t decoy-sandbox:latest sandbox/
python -m uvicorn demo_sites.server:app --port 8601   # our fake sites
python -m uvicorn server:app --port 8020              # Decoy
```
Open http://localhost:8020. Add a Vultr Serverless Inference key to `.env` for the AI agents (without a key only the plain checks run). `DECOY_SANDBOX=local` skips Docker for development only and is **not isolated**. Deploy: Ubuntu 24.04 (2 vCPU / 4 GB), `deploy/setup.sh`, `deploy/gvisor.sh`.

**Built on Vultr:** Cloud Compute (control plane, queue, sandbox host), Serverless Inference (all agents), Firewall Groups (22, 80, 443 only), API (server, firewall, AI subscription).

## Limits
A clean result means nothing harmful was seen **during this visit**; it is not a guarantee. Chromium only, no attachment scanning, CAPTCHAs are not solved, the benchmark is small (read the intervals), and technique labels are suggestions for an analyst to confirm. A person decides.

Tests: `python -m pytest tests -q` · MIT license.
