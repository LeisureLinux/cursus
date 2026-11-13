#!/usr/bin/env bash
# cursus 性能/隐蔽性测试脚本（本地 PC 执行，需要 root 建 TUN）
#
# 前置：VPS 安全组已放行 UDP/443 与 TCP/443；服务端两个实例都已启动。
# 用法：sudo bash scripts/benchmark.sh udp|tcp
set -euo pipefail

mode="${1:-udp}"
case "$mode" in
  udp) cfg=configs/cursus-client.yaml ;;
  tcp) cfg=configs/cursus-client-tcp.yaml ;;
  *) echo "usage: $0 udp|tcp" >&2; exit 2 ;;
esac

echo "=== cursus $mode benchmark ==="
echo "[1] 公网 TCP 握手延迟（不经隧道）"
curl -s -o /dev/null -w '  direct  connect=%{time_connect}s total=%{time_total}s\n' \
  --max-time 5 https://1.1.1.1/cdn-cgi/trace || true

echo "[2] 启动 cursus-client（后台，日志写到 /var/tmp/cursus-bench-$mode.log）"
./bin/cursus -role client -config "$cfg" > "/var/tmp/cursus-bench-$mode.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
sleep 3
if ! grep -q 'state -> connected' "/var/tmp/cursus-bench-$mode.log"; then
  echo "  FAILED: 未连接（检查 VPS 安全组是否已放行）"
  cat "/var/tmp/cursus-bench-$mode.log"
  exit 1
fi
echo "  connected OK"

echo "[3] 加路由并测试经隧道的延迟/吞吐（目标用 speed.cloudflare.com，1.1.1.1 在部分 VPS 不可达）"
if [[ "$mode" == "udp" ]]; then dev=cursus-c0; else dev=cursus-t0; fi
target=$(getent ahostsv4 speed.cloudflare.com | awk 'NR==1{print $1}')
sudo ip route add "$target/32" dev "$dev" 2>/dev/null || true
for i in 1 2 3; do
  curl -s -o /dev/null -w "  tunnel  connect=%{time_connect}s total=%{time_total}s\n" \
    --max-time 10 "https://speed.cloudflare.com/__down?bytes=1000&run=$i" || true
done
echo "[4] 大文件吞吐（10 MB，Cloudflare）"
curl -s -o /dev/null -w '  speed=%{speed_download} B/s size=%{size_download}\n' \
  --max-time 30 https://speed.cloudflare.com/__down?bytes=10000000 || true
sudo ip route del "$target/32" dev "$dev" 2>/dev/null || true

echo "[5] 隐蔽性观察（另开终端在 VPS 上执行）"
echo "  sudo tcpdump -ni eth0 port 443 -X -c 20"
echo "  # TalariaUDP: 无 wire secret 的探测包收不到任何响应，外层已加密"
echo "  # TalariaTCP: 443 上是随机化认证前导码，不是标准 TLS ClientHello"
echo "=== done; log: /var/tmp/cursus-bench-$mode.log ==="
