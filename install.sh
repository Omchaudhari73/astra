#!/bin/bash

set -e

echo "╔════════════════════════════════════════════╗"
echo "║     ASTRA PLATFORM INSTALLER                ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Step 1: System Check
echo "📋 Checking system requirements..."
python3 --version
node --version
npm --version
docker --version

# Step 2: Install Tools
echo "🔧 Installing recon tools..."
bash ~/astra/scripts/install_tools.sh

# Step 3: Setup Database
echo "🗄️ Setting up database..."
bash ~/astra/scripts/init_db.sh

# Step 4: Setup Backend
echo "🐍 Setting up Python backend..."
cd ~/astra/backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Step 5: Setup Frontend
echo "⚛️ Setting up Next.js frontend..."
cd ~/astra/frontend
npm install
npm run build

# Step 6: Set permissions
chmod +x ~/astra/start.sh ~/astra/stop.sh

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║     INSTALLATION COMPLETE!                  ║"
echo "╠════════════════════════════════════════════╣"
echo "║  Run './start.sh' to launch Astra          ║"
echo "╚════════════════════════════════════════════╝"
