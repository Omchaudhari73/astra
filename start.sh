#!/bin/bash

echo "╔════════════════════════════════════════════╗"
echo "║        ASTRA SECURITY PLATFORM              ║"
echo "║        Starting Server...                   ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Kill any existing Astra processes
echo "🧹 Cleaning up old processes..."
pkill -f "python main.py" 2>/dev/null
pkill -f "uvicorn main:app" 2>/dev/null

# Kill anything on port 8000
sudo fuser -k 8000/tcp 2>/dev/null

# Wait for port to be free
sleep 2

# Check if port is free
if sudo lsof -i:8000 &>/dev/null; then
    echo "❌ Port 8000 is still in use!"
    echo "Running processes on port 8000:"
    sudo lsof -i:8000
    echo ""
    echo "Trying port 8001 instead..."
    PORT=8001
else
    PORT=8000
fi

# Start backend
cd ~/astra/backend
source venv/bin/activate

echo "🚀 Starting Astra on port $PORT..."
nohup uvicorn main:app --host 0.0.0.0 --port $PORT --reload > /tmp/astra.log 2>&1 &
PID=$!
echo $PID > /tmp/astra.pid

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 3

# Check if server started successfully
if curl -s http://localhost:$PORT/health > /dev/null 2>&1; then
    echo ""
    echo "╔════════════════════════════════════════════╗"
    echo "║     ✅ ASTRA IS RUNNING!                   ║"
    echo "╠════════════════════════════════════════════╣"
    echo "║  📡 API: http://localhost:$PORT           ║"
    echo "║  📚 Docs: http://localhost:$PORT/docs     ║"
    echo "║  💚 Health: http://localhost:$PORT/health ║"
    echo "╠════════════════════════════════════════════╣"
    echo "║  PID: $PID                                ║"
    echo "║  Logs: tail -f /tmp/astra.log             ║"
    echo "║  Stop: ./stop.sh                          ║"
    echo "║  Test: ./test_api.sh                      ║"
    echo "╚════════════════════════════════════════════╝"
    echo ""
    
    # Show recent logs
    echo "📋 Recent logs:"
    tail -5 /tmp/astra.log
else
    echo ""
    echo "❌ Server failed to start!"
    echo "📋 Error logs:"
    tail -20 /tmp/astra.log
fi
