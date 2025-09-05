#!/usr/bin/env python3
"""
Unit tests for console helper functions.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
import asyncio

# Add the parent directory to the path so we can import modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from console_helpers import (
    execute_module_with_console,
    _setup_module_in_console,
    _setup_payload_in_console,
    _execute_command_in_console,
    _extract_session_id_from_output,
    show_module_options_via_console
)


class TestExtractSessionIdFromOutput:
    """Test session ID extraction from output."""
    
    def test_extract_session_opened(self):
        """Test extracting session ID from 'Session X opened' message."""
        output = "Session 1 opened"
        result = _extract_session_id_from_output(output)
        assert result == 1
    
    def test_extract_meterpreter_session(self):
        """Test extracting session ID from meterpreter session message."""
        output = "meterpreter session 2 opened"
        result = _extract_session_id_from_output(output)
        assert result == 2
    
    def test_extract_command_shell_session(self):
        """Test extracting session ID from command shell session message."""
        output = "Command shell session 3 opened"
        result = _extract_session_id_from_output(output)
        assert result == 3
    
    def test_no_session_found(self):
        """Test when no session ID is found."""
        output = "Module executed successfully"
        result = _extract_session_id_from_output(output)
        assert result is None
    
    def test_invalid_session_id(self):
        """Test with invalid session ID format."""
        output = "Session abc opened"
        result = _extract_session_id_from_output(output)
        assert result is None


class TestSetupModuleInConsole:
    """Test module setup in console."""
    
    @pytest.mark.asyncio
    async def test_successful_setup(self):
        """Test successful module setup."""
        mock_console = Mock()
        
        with patch('console_helpers.run_command_safely') as mock_run_command:
            mock_run_command.side_effect = [
                "msf6 > use exploit/test",  # use command
                "msf6 exploit(test) > set RHOSTS 192.168.1.1",  # set option
                "msf6 exploit(test) > set RPORT 80"  # set option
            ]
            
            result = await _setup_module_in_console(
                mock_console, "exploit/test", 
                {"RHOSTS": "192.168.1.1", "RPORT": 80}, None
            )
            
            assert result["status"] == "success"
            assert result["message"] == "Module setup completed"
    
    @pytest.mark.asyncio
    async def test_module_load_error(self):
        """Test module setup with load error."""
        mock_console = Mock()
        
        with patch('console_helpers.run_command_safely') as mock_run_command:
            mock_run_command.return_value = "[-] Error: Unknown module"
            
            result = await _setup_module_in_console(
                mock_console, "exploit/invalid", {}, None
            )
            
            assert result["status"] == "error"
            assert "Failed to load module" in result["message"]
    
    @pytest.mark.asyncio
    async def test_option_set_error(self):
        """Test module setup with option set error."""
        mock_console = Mock()
        
        with patch('console_helpers.run_command_safely') as mock_run_command:
            mock_run_command.side_effect = [
                "msf6 > use exploit/test",  # use command
                "[-] Error: Invalid option"  # set option error
            ]
            
            result = await _setup_module_in_console(
                mock_console, "exploit/test", 
                {"INVALID_OPTION": "value"}, None
            )
            
            assert result["status"] == "error"
            assert "Error setting option" in result["message"]


class TestSetupPayloadInConsole:
    """Test payload setup in console."""
    
    @pytest.mark.asyncio
    async def test_successful_payload_setup(self):
        """Test successful payload setup."""
        mock_console = Mock()
        
        with patch('console_helpers.run_command_safely') as mock_run_command:
            mock_run_command.side_effect = [
                "msf6 exploit(test) > set PAYLOAD linux/x86/meterpreter/reverse_tcp",
                "msf6 exploit(test) > set LHOST 192.168.1.100",
                "msf6 exploit(test) > set LPORT 4444"
            ]
            
            result = await _setup_payload_in_console(
                mock_console, {
                    "name": "linux/x86/meterpreter/reverse_tcp",
                    "options": {"LHOST": "192.168.1.100", "LPORT": 4444}
                }
            )
            
            assert result["status"] == "success"
            assert result["message"] == "Payload setup completed"
    
    @pytest.mark.asyncio
    async def test_payload_set_error(self):
        """Test payload setup with set error."""
        mock_console = Mock()
        
        with patch('console_helpers.run_command_safely') as mock_run_command:
            mock_run_command.return_value = "[-] Error: Invalid payload"
            
            result = await _setup_payload_in_console(
                mock_console, {"name": "invalid/payload", "options": {}}
            )
            
            assert result["status"] == "error"
            assert "Failed to set payload" in result["message"]
    
    @pytest.mark.asyncio
    async def test_missing_payload_name(self):
        """Test payload setup with missing payload name."""
        mock_console = Mock()
        
        result = await _setup_payload_in_console(
            mock_console, {"options": {}}
        )
        
        assert result["status"] == "error"
        assert "Payload name not specified" in result["message"]


class TestExecuteCommandInConsole:
    """Test command execution in console."""
    
    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """Test successful command execution."""
        mock_console = Mock()
        
        with patch('console_helpers.run_command_safely') as mock_run_command:
            mock_run_command.return_value = "Session 1 opened"
            
            result = await _execute_command_in_console(mock_console, "exploit", 30)
            
            assert result["status"] == "success"
            assert result["session_id"] == 1
            assert "Session 1 opened" in result["module_output"]


class TestShowModuleOptionsViaConsole:
    """Test showing module options via console."""
    
    @pytest.mark.asyncio
    async def test_successful_options_display(self):
        """Test successful options display."""
        with patch('console_helpers.get_msf_console') as mock_get_console:
            mock_console = Mock()
            mock_console_context = AsyncMock()
            mock_console_context.__aenter__ = AsyncMock(return_value=mock_console)
            mock_console_context.__aexit__ = AsyncMock(return_value=None)
            mock_get_console.return_value = mock_console_context
            
            with patch('console_helpers.run_command_safely') as mock_run_command:
                mock_run_command.side_effect = [
                    "msf6 > use exploit/test",
                    "msf6 exploit(test) > set PAYLOAD linux/x86/meterpreter/reverse_tcp",
                    """Module options (exploit/test):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     192.168.1.1     yes       The target host(s)
   RPORT      80               yes       The target port

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.100   yes       The listen address
   LPORT  4444             yes       The listen port"""
                ]
                
                result = await show_module_options_via_console(
                    "exploit/test", "exploit", "linux/x86/meterpreter/reverse_tcp"
                )
                
                assert result["status"] == "success"
                assert result["module_name"] == "exploit/test"
                assert result["payload_name"] == "linux/x86/meterpreter/reverse_tcp"
                assert "Module options" in result["formatted_output"]
    
    @pytest.mark.asyncio
    async def test_module_load_error(self):
        """Test options display with module load error."""
        with patch('console_helpers.get_msf_console') as mock_get_console:
            mock_console = Mock()
            mock_console_context = AsyncMock()
            mock_console_context.__aenter__ = AsyncMock(return_value=mock_console)
            mock_console_context.__aexit__ = AsyncMock(return_value=None)
            mock_get_console.return_value = mock_console_context
            
            with patch('console_helpers.run_command_safely') as mock_run_command:
                mock_run_command.return_value = "[-] Error: Unknown module"
                
                result = await show_module_options_via_console("exploit/invalid")
                
                assert result["status"] == "error"
                assert "Failed to load module" in result["message"]


class TestExecuteModuleWithConsole:
    """Test module execution with console."""
    
    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """Test successful module execution."""
        with patch('console_helpers.get_msf_console') as mock_get_console:
            mock_console = Mock()
            mock_console_context = AsyncMock()
            mock_console_context.__aenter__ = AsyncMock(return_value=mock_console)
            mock_console_context.__aexit__ = AsyncMock(return_value=None)
            mock_get_console.return_value = mock_console_context
            
            with patch('console_helpers._setup_module_in_console') as mock_setup:
                with patch('console_helpers._execute_command_in_console') as mock_execute:
                    mock_setup.return_value = {"status": "success", "message": "Setup completed"}
                    mock_execute.return_value = {
                        "status": "success", 
                        "module_output": "Session 1 opened",
                        "session_id": 1
                    }
                    
                    result = await execute_module_with_console(
                        "exploit", "test", {"RHOSTS": "192.168.1.1"}, "exploit"
                    )
                    
                    assert result["status"] == "success"
                    assert result["session_id"] == 1
    
    @pytest.mark.asyncio
    async def test_setup_error(self):
        """Test module execution with setup error."""
        with patch('console_helpers.get_msf_console') as mock_get_console:
            mock_console = Mock()
            mock_console_context = AsyncMock()
            mock_console_context.__aenter__ = AsyncMock(return_value=mock_console)
            mock_console_context.__aexit__ = AsyncMock(return_value=None)
            mock_get_console.return_value = mock_console_context
            
            with patch('console_helpers._setup_module_in_console') as mock_setup:
                mock_setup.return_value = {"status": "error", "message": "Setup failed"}
                
                result = await execute_module_with_console(
                    "exploit", "test", {"RHOSTS": "192.168.1.1"}, "exploit"
                )
                
                assert result["status"] == "error"
                assert "Setup failed" in result["message"]
