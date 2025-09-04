"""
Configuration for manual tests - these tests are skipped by pytest.
"""

import pytest

# Skip all tests in this directory
pytestmark = pytest.mark.skip(reason="Manual tests - run separately")
