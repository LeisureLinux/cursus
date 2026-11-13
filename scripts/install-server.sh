#!/usr/bin/env bash
# On the server host: install the SINGLE cursus binary (role selected with -role).
# Remote temp files must live in /var/tmp (project rule), never /tmp.
set -euo pipefail
stage=/var/tmp
sudo install -D -m 0755 "$stage/cursus" /usr/bin/cursus
sudo install -D -m 0600 "$stage/cursus-server.yaml" /etc/cursus/cursus-server.yaml
sudo install -D -m 0644 "$stage/cursus-server.service" /usr/lib/systemd/system/cursus-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now cursus-server.service
echo "--- status ---"
sudo systemctl status --no-pager cursus-server.service | head -18
echo "--- listeners ---"
sudo ss -lntup | grep -E ':(443)\b' || true
rm -f "$stage"/cursus "$stage"/cursus-server.yaml "$stage"/cursus-server.service
