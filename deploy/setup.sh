#!/usr/bin/env bash
# Run on a fresh Ubuntu 24.04 Vultr instance as root, with the app unpacked in /opt/decoy and /opt/decoy/.env present.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io python3-venv python3-pip curl
systemctl enable --now docker

cd /opt/decoy
python3 -m venv .venv
.venv/bin/pip install -q fastapi uvicorn httpx
docker build -t decoy-sandbox:latest sandbox/

cat >/etc/systemd/system/decoy-demo.service <<'EOF'
[Unit]
Description=Decoy fake demo sites (private, firewalled)
After=network.target
[Service]
WorkingDirectory=/opt/decoy
ExecStart=/opt/decoy/.venv/bin/uvicorn demo_sites.server:app --host 0.0.0.0 --port 8601
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/decoy.service <<'EOF'
[Unit]
Description=Decoy control plane
After=network.target docker.service
[Service]
WorkingDirectory=/opt/decoy
ExecStart=/opt/decoy/.venv/bin/uvicorn server:app --host 0.0.0.0 --port 80
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now decoy-demo decoy
systemctl --no-pager status decoy decoy-demo | grep -E "Active|Loaded" || true
