#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin"

# Load shell env
for rc in ~/.bashrc ~/.zshrc ~/.profile; do
  [ -f "$rc" ] && source "$rc" 2>/dev/null && break
done

# Start Ollama if installed
if command -v ollama &>/dev/null; then
  if ! curl -s http://localhost:11434/api/tags &>/dev/null 2>&1; then
    echo "[*] Starting Ollama..."
    ollama serve &>/dev/null &
    sleep 3
  fi
fi

echo ""
echo " █████╗ ███████╗████████╗██████╗  █████╗ "
echo "██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗"
echo "███████║███████╗   ██║   ██████╔╝███████║"
echo "██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║"
echo "██║  ██║███████║   ██║   ██║  ██║██║  ██║"
echo "╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo ""
echo "  Web UI  →  http://localhost:5000"
echo "  Ctrl+C to stop"
echo ""

python3 app.py
