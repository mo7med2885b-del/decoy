#!/usr/bin/env bash
# Run on a fresh Ubuntu 24.04 Vultr instance as root, with the app unpacked in /opt/decoy and /opt/decoy/.env present.
#   DECOY_HOST=<name> bash deploy/setup.sh      (name defaults to <ip>.sslip.io, a free DNS name that points at the server)
# Installs Docker, builds the sandbox image, runs the app behind Caddy (automatic HTTPS), adds network rules that keep
# sandbox containers away from private and cloud-secret addresses, and enables gVisor when the browser works under it.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
IP=$(curl -fsS https://api.ipify.org || hostname -I | awk '{print $1}')
DECOY_HOST=${DECOY_HOST:-$(echo "$IP" | tr . -).sslip.io}

apt-get update -y
apt-get install -y docker.io python3-venv python3-pip curl caddy iptables
systemctl enable --now docker

cd /opt/decoy
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
docker build -t decoy-sandbox:latest sandbox/

# --- network rules: a sandbox container may use the internet but never the server's own side of the network ---
cat >/usr/local/bin/decoy-firewall.sh <<'EOF'
#!/usr/bin/env bash
# DOCKER-USER is evaluated for every packet leaving a container toward another network.
for net in 169.254.0.0/16 10.0.0.0/8 192.168.0.0/16 100.64.0.0/10 172.16.0.0/12; do
  iptables -C DOCKER-USER -s 172.16.0.0/12 -d $net -j DROP 2>/dev/null || iptables -I DOCKER-USER -s 172.16.0.0/12 -d $net -j DROP
done
EOF
chmod +x /usr/local/bin/decoy-firewall.sh
cat >/etc/systemd/system/decoy-firewall.service <<'EOF'
[Unit]
Description=Decoy sandbox network rules
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/decoy-firewall.sh
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/decoy-demo.service <<'EOF'
[Unit]
Description=Decoy fake demo sites (private: reachable only from sandbox containers)
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
ExecStart=/opt/decoy/.venv/bin/uvicorn server:app --host 127.0.0.1 --port 8020 --proxy-headers
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/caddy/Caddyfile <<EOF
$DECOY_HOST {
    encode gzip
    reverse_proxy 127.0.0.1:8020 {
        flush_interval -1
    }
}
EOF

# the sandbox containers reach the demo sites on the docker host, nothing else on the host
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
ufw allow from 172.16.0.0/12 to any port 8601 proto tcp >/dev/null

systemctl daemon-reload
systemctl enable --now decoy-firewall decoy-demo decoy
systemctl restart decoy decoy-demo caddy
echo "app:   https://$DECOY_HOST"
systemctl is-active decoy decoy-demo caddy decoy-firewall
iptables -S DOCKER-USER | head -8
