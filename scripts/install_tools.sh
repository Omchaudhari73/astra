#!/bin/bash

echo "🔧 Installing Reconnaissance Tools for Astra..."

# Install Go tools
echo "Installing Go-based tools..."

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/local/bin/

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/httpx /usr/local/bin/

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/

# Naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
sudo cp ~/go/bin/naabu /usr/local/bin/

# Dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
sudo cp ~/go/bin/dnsx /usr/local/bin/

# Katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
sudo cp ~/go/bin/katana /usr/local/bin/

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master
sudo cp ~/go/bin/amass /usr/local/bin/

# Assetfinder
go install -v github.com/tomnomnom/assetfinder@latest
sudo cp ~/go/bin/assetfinder /usr/local/bin/

# GAU
go install -v github.com/lc/gau/v2/cmd/gau@latest
sudo cp ~/go/bin/gau /usr/local/bin/

# Waybackurls
go install -v github.com/tomnomnom/waybackurls@latest
sudo cp ~/go/bin/waybackurls /usr/local/bin/

# Install Findomain
echo "Installing Findomain..."
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

# Install WhatWeb
echo "Installing WhatWeb..."
sudo apt install -y whatweb

# Download Nuclei Templates
echo "Downloading Nuclei Templates..."
nuclei -update-templates

# Install Python tools
echo "Installing Python tools..."
pip install dirsearch wfuzz arjun

# Create tool verification script
cat > /usr/local/bin/astra-tools-check << 'CHECK'
#!/bin/bash
echo "🔍 Checking Astra Recon Tools..."
tools=("subfinder" "amass" "assetfinder" "findomain" "httpx" "naabu" "dnsx" "katana" "gau" "waybackurls" "whatweb" "nuclei")

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "✅ $tool is installed"
    else
        echo "❌ $tool is missing"
    fi
done
CHECK

chmod +x /usr/local/bin/astra-tools-check
echo "✅ All tools installed successfully!"
astra-tools-check
