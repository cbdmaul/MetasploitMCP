#!/bin/bash
"""
Test runner script for MetasploitMCP console output capture fix.
"""

echo "MetasploitMCP Console Output Capture Fix - Test Runner"
echo "======================================================"

# Check if Metasploit is running
echo "Checking Metasploit RPC server..."
if ! pgrep -f "msfrpcd" > /dev/null; then
    echo "❌ Metasploit RPC server is not running!"
    echo "Please start it with: msfrpcd -P password -S"
    exit 1
fi
echo "✅ Metasploit RPC server is running"

# Check if MCP server is running (for HTTP tests)
echo "Checking MCP server..."
if ! curl -s http://127.0.0.1:8088/mcp > /dev/null 2>&1; then
    echo "⚠️ MCP server is not running on port 8088"
    echo "Starting MCP server in background..."
    python MetasploitMCP.py --transport http --port 8088 &
    MCP_PID=$!
    sleep 5
    
    if ! curl -s http://127.0.0.1:8088/mcp > /dev/null 2>&1; then
        echo "❌ Failed to start MCP server"
        exit 1
    fi
    echo "✅ MCP server started (PID: $MCP_PID)"
else
    echo "✅ MCP server is running"
fi

echo ""
echo "Running FastMCP client test..."
echo "=============================="

# FastMCP client test
if command -v python >/dev/null 2>&1 && python -c "import fastmcp" 2>/dev/null; then
    echo ""
    echo "FastMCP Client Test"
    echo "-------------------"
    python test_fastmcp_client.py 10.77.0.149
else
    echo ""
    echo "FastMCP Client Test (SKIPPED - fastmcp not available)"
    echo "Install with: pip install fastmcp"
    echo "-----------------------------------------------------"
fi

echo ""
echo "Tests completed!"
echo "================"

# Clean up background MCP server if we started it
if [ ! -z "$MCP_PID" ]; then
    echo "Stopping background MCP server (PID: $MCP_PID)..."
    kill $MCP_PID
fi
