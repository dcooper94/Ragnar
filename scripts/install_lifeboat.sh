#!/bin/bash
# Install Ragnar Lifeboat — always-on service swap UI on port 8001

set -e

RAGNAR_PATH="/home/ragnar/Ragnar"
SERVICE_FILE="/etc/systemd/system/ragnar-lifeboat.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash scripts/install_lifeboat.sh"
    exit 1
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ragnar Lifeboat - Service Swap Interface
Documentation=https://github.com/dcooper94/Ragnar
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 ${RAGNAR_PATH}/lifeboat.py
Restart=always
RestartSec=5
KillMode=process
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
chmod +x "$RAGNAR_PATH/lifeboat.py"

systemctl daemon-reload
systemctl enable ragnar-lifeboat
systemctl restart ragnar-lifeboat

sleep 2
STATUS=$(systemctl is-active ragnar-lifeboat)
if [ "$STATUS" = "active" ]; then
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "Ragnar Lifeboat is running!"
    echo "  http://${IP}:8001"
    echo ""
    echo "Bookmark that URL. It stays up regardless of which mode you are in."
else
    echo "Service failed to start. Check: sudo journalctl -u ragnar-lifeboat -f"
    exit 1
fi
