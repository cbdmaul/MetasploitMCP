# MetasploitMCP Integration Test

This directory contains a FastMCP client test to verify the console output capture fix for MetasploitMCP.

## Test Script

### `test_fastmcp_client.py` - FastMCP Client Test
Tests the MCP server using the official FastMCP client by running real Metasploit exploits.

**Usage:**
```bash
# Test against a running MCP server
python test_fastmcp_client.py <target_ip> [server_url]

# Examples:
python test_fastmcp_client.py 10.77.0.149
python test_fastmcp_client.py 10.77.0.149 http://127.0.0.1:8088/mcp
```

**What it tests:**
- FastMCP client connection to HTTP MCP server
- Tool listing and discovery
- Auxiliary module execution (port scan)
- Exploit module execution (FTP exploit)
- Session management
- Console output capture verification

## Prerequisites

1. **Metasploit Framework** must be installed and running
2. **MCP server** must be running
3. **Python dependencies** installed:
   ```bash
   pip install fastmcp
   ```

## Running the Test

### Step 1: Start the MCP Server
```bash
# Start the MCP server in HTTP mode
python MetasploitMCP.py --transport http --port 8088
```

### Step 2: Run the Test

#### FastMCP Client Test
```bash
# Test against a real target
python test_fastmcp_client.py 10.77.0.149

# Test against localhost
python test_fastmcp_client.py 127.0.0.1

# Or run the automated test runner
./run_tests.sh
```

## Expected Results

### Before the Fix
- `module_output` would contain only configuration options
- Output would be truncated or incomplete
- Exploit execution results would be missing

### After the Fix
- `module_output` should contain full exploit execution results
- Output should include exploit progress, success/failure indicators
- Session information should be properly captured

### Example Expected Output
```
[-] Handler failed to bind to 10.77.0.189:4444:-  -
[*] Started reverse TCP handler on 0.0.0.0:4444
[*] 10.77.0.149:80 - 10.77.0.149:21 - Connected to FTP server
[*] 10.77.0.149:80 - 10.77.0.149:21 - Sending copy commands to FTP server
[*] 10.77.0.149:80 - Executing PHP payload /Hn5997l.php
[+] 10.77.0.149:80 - Deleted /var/www/html/Hn5997l.php
[*] Command shell session 1 opened (172.19.208.185:4444 -> 172.19.208.1:53406) at 2025-09-04 11:57:31 -0400
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Ensure the MCP server is running
   - Check the server URL/port

2. **Metasploit Not Found**
   - Ensure Metasploit Framework is installed
   - Check MSF RPC server is running

3. **Import Errors**
   - Ensure all dependencies are installed
   - Check Python path

4. **Test Failures**
   - Check target IP is reachable
   - Verify target has vulnerable services
   - Check firewall settings

### Debug Mode
Enable debug logging by modifying the logging level:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Test Results Interpretation

- ✅ **PASSED**: Test completed successfully with expected results
- ⚠️ **PARTIAL**: Test completed but results may be incomplete
- ❌ **FAILED**: Test failed with errors

The tests will provide detailed output analysis and recommendations for any issues found.
