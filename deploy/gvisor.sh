#!/usr/bin/env bash
# Optional: install gVisor (runsc) as an extra Docker runtime and test that the sandbox browser really runs under it.
# Prints GVISOR_OK when it does. Only then set DECOY_SANDBOX_RUNTIME=runsc in /opt/decoy/.env.
set -uo pipefail
ARCH=$(uname -m)
URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
cd /tmp
curl -fsSLO "$URL/runsc" -O "$URL/runsc.sha512" || { echo "download failed"; exit 1; }
sha512sum -c runsc.sha512 || exit 1
install -m 755 runsc /usr/local/bin/runsc
/usr/local/bin/runsc install
systemctl restart docker
sleep 3
if docker run --rm --runtime=runsc --entrypoint python decoy-sandbox:latest -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True, args=['--disable-dev-shm-usage'])
    pg = b.new_page(); pg.set_content('<title>gv</title>ok'); print('TITLE', pg.title()); b.close()
" 2>&1 | tee /tmp/gv.out | grep -q "TITLE gv"; then echo GVISOR_OK; else echo GVISOR_FAILED; tail -5 /tmp/gv.out; fi
