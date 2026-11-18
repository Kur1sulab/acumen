#!/usr/bin/env bash
# 启动 鉴微：默认监听 127.0.0.1:7788 并自动打开浏览器。
# 收件箱默认：~/pentest-inbox（新产物丢这里）、~/pentest、~/pentest-assets
# 自定义：  ./run.sh --inbox ~/某个目录 --port 7799       （参数原样透传给 server.py）
set -euo pipefail
cd "$(dirname "$0")"
PORT=7788
for ((i = 1; i <= $#; i++)); do
  if [[ "${!i}" == "--port" ]]; then j=$((i + 1)); PORT="${!j}"; fi
done
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[acumen] 端口 $PORT 已被占用，直接打开已有实例"
  open "http://127.0.0.1:$PORT/"
  exit 0
fi
exec python3 -m vc.server --port "$PORT" --open "$@"
