#!/usr/bin/env python3
"""
Simple test script to verify the console output capture fix.
This script tests the console execution logic directly without requiring a full MCP server.
"""

import asyncio
import logging
import sys
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_console_execution():
    """Test the console execution logic directly."""
    try:
        # Import the console utilities
        from console_utils import get_msf_console, run_command_safely, set_msf_client
        from MetasploitMCP import initialize_msf_connection, get_msf_client
        
        logger.info("Testing console execution fix...")
        
        # Initialize MSF connection
        logger.info("Initializing MSF connection...")
        client = await initialize_msf_connection()
        set_msf_client(client)
        
        # Test console execution with a simple command
        logger.info("Testing console execution with 'version' command...")
        
        async with get_msf_console() as console:
            # Test a simple command first
            result = await run_command_safely(console, "version", execution_timeout=15)
            logger.info(f"Version command result (length: {len(result)}):")
            print(result[:500])
            if len(result) > 500:
                print("...")
            
            # Test exploit command (this should show the improved output capture)
            logger.info("Testing exploit command execution...")
            logger.info("Note: This will test the console output capture logic")
            
            # Use a simple exploit that's likely to work
            exploit_result = await run_command_safely(console, "use exploit/unix/ftp/proftpd_133c_backdoor", execution_timeout=15)
            logger.info(f"Use command result (length: {len(exploit_result)}):")
            print(exploit_result[:200])
            if len(exploit_result) > 200:
                print("...")
            
            # Test setting options
            set_result = await run_command_safely(console, "set RHOSTS 127.0.0.1", execution_timeout=15)
            logger.info(f"Set RHOSTS result (length: {len(set_result)}):")
            print(set_result[:100])
            
            set_result = await run_command_safely(console, "set RPORT 21", execution_timeout=15)
            logger.info(f"Set RPORT result (length: {len(set_result)}):")
            print(set_result[:100])
            
            # Test the actual exploit command (this is where the fix should show)
            logger.info("Testing 'run' command (this should capture full output)...")
            run_result = await run_command_safely(console, "run", execution_timeout=90)
            logger.info(f"Run command result (length: {len(run_result)}):")
            print(run_result)
            
            # Analyze the result
            if len(run_result) > 100:
                logger.info("✅ Console execution test PASSED - Got substantial output")
                
                # Check for exploit indicators
                if any(indicator in run_result.lower() for indicator in 
                      ["session", "opened", "exploit", "handler", "payload", "connected", "failed"]):
                    logger.info("✅ Found exploit execution indicators in output")
                else:
                    logger.warning("⚠️ No clear exploit indicators found")
            else:
                logger.warning("⚠️ Console execution test PARTIAL - Output may be incomplete")
                logger.info(f"Output: {run_result}")
        
        logger.info("Console execution test completed")
        
    except Exception as e:
        logger.error(f"Console execution test failed: {e}")
        raise

async def main():
    """Main test function."""
    logger.info("Starting console execution fix test")
    
    try:
        await test_console_execution()
        logger.info("✅ All tests completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
