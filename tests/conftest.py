#!/usr/bin/env python3
"""
Test configuration and fixtures for MetasploitMCP tests.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
import sys
import os

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mock_msf_client():
    """Mock MSF RPC client for testing."""
    client = Mock()
    client.modules.exploits = []
    client.modules.payloads = []
    client.sessions.list = {}
    client.jobs.list = {}
    client.core.version = {"version": "6.0.0"}
    return client


@pytest.fixture
def mock_console():
    """Mock MSF console for testing."""
    console = Mock()
    console.read.return_value = ""
    console.write.return_value = None
    return console


@pytest.fixture
def mock_console_context():
    """Mock console context manager for testing."""
    console = Mock()
    console.read.return_value = ""
    console.write.return_value = None
    
    context = AsyncMock()
    context.__aenter__ = AsyncMock(return_value=console)
    context.__aexit__ = AsyncMock(return_value=None)
    
    return context


@pytest.fixture
def mock_module():
    """Mock MSF module for testing."""
    module = Mock()
    module.fullname = "exploit/test/module"
    module.options = {
        "RHOSTS": {"type": "string", "required": True, "description": "Target host"},
        "RPORT": {"type": "int", "required": True, "description": "Target port"}
    }
    module.execute.return_value = {"job_id": 123, "uuid": "test-uuid"}
    return module


@pytest.fixture
def mock_payload():
    """Mock MSF payload for testing."""
    payload = Mock()
    payload.fullname = "payload/test/payload"
    payload.options = {
        "LHOST": {"type": "string", "required": True, "description": "Local host"},
        "LPORT": {"type": "int", "required": True, "description": "Local port"}
    }
    payload.payload_generate.return_value = b"fake_payload_data"
    return payload


@pytest.fixture
def mock_session():
    """Mock MSF session for testing."""
    session = Mock()
    session.read.return_value = "Command output"
    session.write.return_value = None
    session.stop.return_value = None
    return session


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Add unit marker for tests in unit directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        
        # Add integration marker for tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Add slow marker for tests with "slow" in the name
        if "slow" in item.name:
            item.add_marker(pytest.mark.slow)
