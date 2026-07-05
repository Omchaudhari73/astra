#!/bin/bash

echo "🛑 Stopping Astra Platform..."

# Kill by PID file
if [ -f /tmp/astra.pid ]; then
    PID=$(cat /tmp/astra.pid)
    kill $PID 2>/dev/null
    echo "✅ Killed process $PID"
    rm /tmp/astra.pid
fi

# Kill any remaining uvicorn processes
pkill -f "uvicorn main:app" 2>/dev/null
pkill -f "python main.py" 2>/dev/null

# Free up ports
sudo fuser -k 8000/tcp 2>/dev/null
sudo fuser -k 8001/tcp 2>/dev/null

sleep 1

echo "✅ Astra Platform stopped!"
