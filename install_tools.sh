#!/usr/bin/env bash
set -e
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'

echo -e "${CYAN}[*]${RESET} Installing security tools for Astra..."

# Go tools
if command -v go &>/dev/null; then
  echo -e "${CYAN}[*]${RESET} Installing Go-based tools..."
  GOPATH=$(go env GOPATH)
  export PATH="$PATH:$GOPATH/bin"
  
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} subfinder" || echo -e "${YELLOW}[!]${RESET} subfinder failed"
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} httpx" || echo -e "${YELLOW}[!]${RESET} httpx failed"
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} nuclei" || echo -e "${YELLOW}[!]${RESET} nuclei failed"
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} katana" || echo -e "${YELLOW}[!]${RESET} katana failed"
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} dnsx" || echo -e "${YELLOW}[!]${RESET} dnsx failed"
  go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} gau" || echo -e "${YELLOW}[!]${RESET} gau failed"
  go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} dalfox" || echo -e "${YELLOW}[!]${RESET} dalfox failed"
  go install -v github.com/OJ/gobuster/v3@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} gobuster" || echo -e "${YELLOW}[!]${RESET} gobuster failed"
  go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null && echo -e "${GREEN}[✓]${RESET} ffuf" || echo -e "${YELLOW}[!]${RESET} ffuf failed"
else
  echo -e "${YELLOW}[!]${RESET} Go not found, skipping Go tools. Install from golang.org"
fi

# APT tools (Kali usually has these)
echo -e "${CYAN}[*]${RESET} Installing apt tools..."
sudo apt-get install -y -qq nmap sqlmap nikto whatweb 2>/dev/null || true
echo -e "${GREEN}[✓]${RESET} apt tools done"

# Python tools
echo -e "${CYAN}[*]${RESET} Installing Python tools..."
pip3 install --break-system-packages --quiet arjun 2>/dev/null || pip3 install --quiet arjun 2>/dev/null || true
echo -e "${GREEN}[✓]${RESET} arjun done"

# Update nuclei templates
if command -v nuclei &>/dev/null; then
  echo -e "${CYAN}[*]${RESET} Updating nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null || true
  echo -e "${GREEN}[✓]${RESET} Templates updated"
fi

echo ""
echo -e "${GREEN}[✓]${RESET} Tool installation complete!"
echo "Run ./run.sh to start Astra"
