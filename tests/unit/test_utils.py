#!/usr/bin/env python3
"""
Unit tests for utility functions.
"""

import pytest
from unittest.mock import Mock, patch
import asyncio

# Add the parent directory to the path so we can import utils
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    normalize_module_path,
    normalize_payload_name,
    get_module_fullname,
    safe_rpc_call,
    check_console_error,
    format_options_output,
    create_error_response,
    create_success_response,
    validate_session_id,
    validate_job_id,
    extract_module_info_from_output,
    parse_options_from_formatted_output
)


class TestNormalizeModulePath:
    """Test module path normalization."""
    
    def test_simple_module_name(self):
        """Test normalizing a simple module name."""
        result = normalize_module_path("vsftpd_234_backdoor", "exploit")
        assert result == "exploit/vsftpd_234_backdoor"
    
    def test_full_module_path(self):
        """Test normalizing a full module path."""
        result = normalize_module_path("exploit/unix/ftp/vsftpd_234_backdoor", "exploit")
        assert result == "exploit/unix/ftp/vsftpd_234_backdoor"
    
    def test_relative_module_path(self):
        """Test normalizing a relative module path."""
        result = normalize_module_path("unix/ftp/vsftpd_234_backdoor", "exploit")
        assert result == "exploit/unix/ftp/vsftpd_234_backdoor"
    
    def test_payload_module_path(self):
        """Test normalizing a payload module path."""
        result = normalize_module_path("payload/linux/x86/meterpreter/reverse_tcp", "payload")
        assert result == "payload/linux/x86/meterpreter/reverse_tcp"


class TestNormalizePayloadName:
    """Test payload name normalization."""
    
    def test_payload_with_prefix(self):
        """Test normalizing payload name with payload/ prefix."""
        result = normalize_payload_name("payload/linux/x86/meterpreter/reverse_tcp")
        assert result == "linux/x86/meterpreter/reverse_tcp"
    
    def test_payload_without_prefix(self):
        """Test normalizing payload name without payload/ prefix."""
        result = normalize_payload_name("linux/x86/meterpreter/reverse_tcp")
        assert result == "linux/x86/meterpreter/reverse_tcp"
    
    def test_simple_payload_name(self):
        """Test normalizing simple payload name."""
        result = normalize_payload_name("reverse_tcp")
        assert result == "reverse_tcp"


class TestGetModuleFullname:
    """Test getting module fullname."""
    
    def test_module_with_fullname(self):
        """Test getting fullname from module with fullname attribute."""
        mock_module = Mock()
        mock_module.fullname = "exploit/unix/ftp/vsftpd_234_backdoor"
        
        result = get_module_fullname(mock_module, "exploit", "vsftpd_234_backdoor")
        assert result == "exploit/unix/ftp/vsftpd_234_backdoor"
    
    def test_module_without_fullname(self):
        """Test getting fullname from module without fullname attribute."""
        mock_module = Mock()
        del mock_module.fullname  # Remove the attribute
        
        result = get_module_fullname(mock_module, "exploit", "vsftpd_234_backdoor")
        assert result == "exploit/vsftpd_234_backdoor"


class TestSafeRpcCall:
    """Test safe RPC call function."""
    
    @pytest.mark.asyncio
    async def test_successful_call(self):
        """Test successful RPC call."""
        def mock_func(x, y):
            return x + y
        
        result = await safe_rpc_call(mock_func, 2, 3)
        assert result == 5
    
    @pytest.mark.asyncio
    async def test_timeout(self):
        """Test RPC call timeout."""
        def slow_func():
            import time
            time.sleep(2)
            return "done"
        
        with pytest.raises(asyncio.TimeoutError):
            await safe_rpc_call(slow_func, timeout=0.1)
    
    @pytest.mark.asyncio
    async def test_exception_handling(self):
        """Test RPC call exception handling."""
        def failing_func():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError, match="Test error"):
            await safe_rpc_call(failing_func)


class TestCheckConsoleError:
    """Test console error checking."""
    
    def test_no_error(self):
        """Test output with no errors."""
        output = "Module options (exploit/unix/ftp/vsftpd_234_backdoor):\n\n   Name       Current Setting  Required  Description"
        has_error, message = check_console_error(output)
        assert not has_error
        assert message == ""
    
    def test_error_detected(self):
        """Test output with error detected."""
        output = "[-] Error: Unknown module 'invalid/module'"
        has_error, message = check_console_error(output)
        assert has_error
        assert "Error detected: [-] Error" in message
    
    def test_custom_error_patterns(self):
        """Test with custom error patterns."""
        output = "Custom error message"
        has_error, message = check_console_error(output, ["Custom error"])
        assert has_error
        assert "Error detected: Custom error" in message


class TestFormatOptionsOutput:
    """Test options output formatting."""
    
    def test_basic_formatting(self):
        """Test basic options output formatting."""
        module_name = "exploit/unix/ftp/vsftpd_234_backdoor"
        payload_name = "linux/x86/meterpreter/reverse_tcp"
        options_output = "Module options:\n   Name    Current Setting  Required  Description"
        
        result = format_options_output(module_name, payload_name, options_output)
        
        assert result["status"] == "success"
        assert result["module_name"] == module_name
        assert result["payload_name"] == payload_name
        assert result["formatted_output"] == options_output
    
    def test_no_payload(self):
        """Test formatting without payload."""
        module_name = "auxiliary/scanner/ssh/ssh_login"
        options_output = "Module options:\n   Name    Current Setting  Required  Description"
        
        result = format_options_output(module_name, None, options_output)
        
        assert result["status"] == "success"
        assert result["module_name"] == module_name
        assert result["payload_name"] is None


class TestCreateErrorResponse:
    """Test error response creation."""
    
    def test_basic_error(self):
        """Test basic error response."""
        result = create_error_response("Test error")
        assert result["status"] == "error"
        assert result["message"] == "Test error"
    
    def test_error_with_module(self):
        """Test error response with module context."""
        result = create_error_response("Test error", "exploit/test")
        assert result["status"] == "error"
        assert result["message"] == "Test error"
        assert result["module"] == "exploit/test"


class TestCreateSuccessResponse:
    """Test success response creation."""
    
    def test_basic_success(self):
        """Test basic success response."""
        result = create_success_response("Test success")
        assert result["status"] == "success"
        assert result["message"] == "Test success"
    
    def test_success_with_extra_fields(self):
        """Test success response with extra fields."""
        result = create_success_response("Test success", data={"key": "value"}, count=5)
        assert result["status"] == "success"
        assert result["message"] == "Test success"
        assert result["data"] == {"key": "value"}
        assert result["count"] == 5


class TestValidateSessionId:
    """Test session ID validation."""
    
    def test_valid_session_id(self):
        """Test valid session ID."""
        is_valid, message = validate_session_id(1)
        assert is_valid
        assert message == ""
    
    def test_invalid_negative_session_id(self):
        """Test invalid negative session ID."""
        is_valid, message = validate_session_id(-1)
        assert not is_valid
        assert "must be a non-negative integer" in message
    
    def test_invalid_string_session_id(self):
        """Test invalid string session ID."""
        is_valid, message = validate_session_id("1")
        assert not is_valid
        assert "must be a non-negative integer" in message


class TestValidateJobId:
    """Test job ID validation."""
    
    def test_valid_job_id(self):
        """Test valid job ID."""
        is_valid, message = validate_job_id(123)
        assert is_valid
        assert message == ""
    
    def test_invalid_negative_job_id(self):
        """Test invalid negative job ID."""
        is_valid, message = validate_job_id(-1)
        assert not is_valid
        assert "must be a non-negative integer" in message


class TestExtractModuleInfoFromOutput:
    """Test module info extraction from output."""
    
    def test_extract_module_info(self):
        """Test extracting module info from console output."""
        output = "msf6 exploit(unix/ftp/vsftpd_234_backdoor) > show options"
        result = extract_module_info_from_output(output)
        
        assert result["module_type"] == "exploit"
        assert result["module_name"] == "unix/ftp/vsftpd_234_backdoor"
    
    def test_no_module_info(self):
        """Test output with no module info."""
        output = "msf6 > help"
        result = extract_module_info_from_output(output)
        
        assert result == {}


class TestParseOptionsFromFormattedOutput:
    """Test parsing options from formatted output."""
    
    def test_parse_module_options(self):
        """Test parsing module options from formatted output."""
        output = """Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     192.168.1.1     yes       The target host(s)
   RPORT      21               yes       The target port

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.100   yes       The listen address
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   ProFTPD 1.3.5"""
        
        result = parse_options_from_formatted_output(output)
        
        assert result["module_options"]["module_name"] == "exploit/unix/ftp/vsftpd_234_backdoor"
        assert result["payload_options"]["payload_name"] == "linux/x86/meterpreter/reverse_tcp"
        assert result["exploit_targets"] == []
    
    def test_parse_empty_output(self):
        """Test parsing empty output."""
        result = parse_options_from_formatted_output("")
        
        assert result["module_options"] == {}
        assert result["payload_options"] == {}
        assert result["exploit_targets"] == []
