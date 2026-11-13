#!/usr/bin/env bash
# Print (do not apply) the nft input rules for cursus. The VPS security group
# still needs the same UDP/TCP ports opened by the operator.
set -euo pipefail
cat <<'RULES'
# /etc/nftables.conf.d/cursus-input.nft (apply manually if host firewall is used)
table inet cursus_input {
  chain input {
    type filter hook input priority filter; policy accept;
    udp dport 443 accept   # TalariaUDP
    tcp dport 443 accept     # TalariaTCP (also 443 for the public certificate)
  }
}
RULES
echo
echo "VPS security group: open UDP/443 and TCP/443 to 0.0.0.0/0 and ::/0"
