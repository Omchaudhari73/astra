#!/bin/bash

# Check if port is provided
PORT=${1:-8000}

echo "🧪 Testing Astra API on port $PORT..."
echo ""

# Test 1: Health Check
echo "1️⃣ Health Check:"
RESPONSE=$(curl -s http://localhost:$PORT/health)
if [ $? -eq 0 ]; then
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
fi
echo ""

# Test 2: Root
echo "2️⃣ Root Endpoint:"
curl -s http://localhost:$PORT/ | python3 -m json.tool 2>/dev/null
echo ""

# Test 3: Dashboard Stats
echo "3️⃣ Dashboard Stats:"
curl -s http://localhost:$PORT/api/dashboard/stats | python3 -m json.tool 2>/dev/null
echo ""

# Test 4: Agent Status
echo "4️⃣ Agent Status:"
curl -s http://localhost:$PORT/api/agents/status | python3 -m json.tool 2>/dev/null
echo ""

# Test 5: Create Workspace
echo "5️⃣ Create Workspace:"
WS_RESPONSE=$(curl -s -X POST http://localhost:$PORT/api/workspaces \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Bug Bounty",
    "description": "Testing Astra Platform",
    "target_domains": ["example.com"],
    "ai_provider": "openai"
  }')
echo "$WS_RESPONSE" | python3 -m json.tool 2>/dev/null

# Extract workspace ID
WS_ID=$(echo "$WS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
echo ""

# Test 6: List Workspaces
echo "6️⃣ List Workspaces:"
curl -s http://localhost:$PORT/api/workspaces | python3 -m json.tool 2>/dev/null
echo ""

# Test 7: Create Finding
if [ ! -z "$WS_ID" ]; then
    echo "7️⃣ Create Finding:"
    curl -s -X POST http://localhost:$PORT/api/findings \
      -H "Content-Type: application/json" \
      -d "{
        \"workspace_id\": \"$WS_ID\",
        \"title\": \"SQL Injection in Login\",
        \"description\": \"Found SQL injection vulnerability in login form\",
        \"severity\": \"critical\",
        \"asset_url\": \"https://example.com/login\"
      }" | python3 -m json.tool 2>/dev/null
    echo ""
fi

# Test 8: Search
echo "8️⃣ Search Test:"
curl -s "http://localhost:$PORT/api/search?query=SQL" | python3 -m json.tool 2>/dev/null
echo ""

# Test 9: Recon Tools
echo "9️⃣ Available Recon Tools:"
curl -s http://localhost:$PORT/api/agents/providers | python3 -m json.tool 2>/dev/null
echo ""

echo "✅ API Testing Complete!"
echo ""
echo "Access the interactive docs at: http://localhost:$PORT/docs"
