#!/usr/bin/env bash
# Optional: install gVisor (runsc) as an extra Docker runtime and test that the sandbox browser really runs under it.
# Prints GVISOR_OK when it does. Only then set DECOY_SANDBOX_RUNTIME=runsc in /opt/decoy/.env.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg || exit 1
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  >/etc/apt/sources.list.d/gvisor.list
apt-get update -y >/dev/null && apt-get install -y runsc || { echo "install failed"; exit 1; }
runsc install
systemctl restart docker
sleep 4
if docker run --rm --runtime=runsc --entrypoint python decoy-sandbox:latest -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True, args=['--disable-dev-shm-usage'])
    pg = b.new_page(); pg.set_content('<title>gv</title>ok'); print('TITLE', pg.title()); b.close()
" 2>&1 | tee /tmp/gv.out | grep -q "TITLE gv"; then echo GVISOR_OK; else echo GVISOR_FAILED; tail -6 /tmp/gv.out; fi
