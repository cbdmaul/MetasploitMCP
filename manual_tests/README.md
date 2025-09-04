# Manual Tests

This directory contains manual test scripts that are not automatically executed by pytest.

## Test Files

- `test_fastmcp_client.py` - Tests the FastMCP client integration
- `test_console_fix.py` - Tests console execution logic directly
- `test_listener_fix.py` - Tests listener functionality
- `run_tests.py` - Manual test runner script
- `run_all_tests.py` - Comprehensive test runner

## Usage

These tests require specific setup and are meant to be run manually:

```bash
# Run individual tests
python tests/manual/test_console_fix.py
python tests/manual/test_fastmcp_client.py

# Run all manual tests
python tests/manual/run_all_tests.py
```

## Requirements

- Metasploit RPC server running
- pymetasploit3 installed
- FastMCP client (for client tests)

These tests are excluded from the main pytest suite to avoid dependency issues and because they require external services.
