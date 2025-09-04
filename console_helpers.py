# -*- coding: utf-8 -*-
"""
Console helper functions for MetasploitMCP to reduce duplication in console operations.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from utils import (
    normalize_module_path,
    normalize_payload_name,
    check_console_error,
    format_options_output,
    create_error_response,
    create_success_response
)

logger = logging.getLogger(__name__)

# Import console utilities
from console_utils import get_msf_console, run_command_safely, DEFAULT_CONSOLE_READ_TIMEOUT


async def execute_module_with_console(
    module_type: str,
    module_name: str,
    module_options: Dict[str, Any],
    command: str,
    payload_spec: Optional[Dict[str, Any]] = None,
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Execute a module via console with proper setup and error handling.
    
    Args:
        module_type: Type of module ('exploit', 'auxiliary', 'post')
        module_name: Name/path of the module
        module_options: Dictionary of module options
        command: Command to execute ('exploit', 'run', 'check')
        payload_spec: Optional payload specification
        timeout: Timeout in seconds
        
    Returns:
        Dictionary with execution results
    """
    full_module_path = normalize_module_path(module_name, module_type)
    
    async with get_msf_console() as console:
        try:
            # Setup module
            setup_result = await _setup_module_in_console(
                console, full_module_path, module_options, payload_spec
            )
            if setup_result["status"] != "success":
                return setup_result
            
            # Execute command
            execution_result = await _execute_command_in_console(
                console, command, timeout
            )
            return execution_result
            
        except Exception as e:
            logger.exception(f"Unexpected error executing {full_module_path}")
            return create_error_response(f"Unexpected error: {e}", full_module_path)


async def _setup_module_in_console(
    console: Any,
    full_module_path: str,
    module_options: Dict[str, Any],
    payload_spec: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Setup a module in console with options and payload.
    
    Args:
        console: The console object
        full_module_path: Full path to the module
        module_options: Module options
        payload_spec: Optional payload specification
        
    Returns:
        Setup result dictionary
    """
    # Use the module
    use_output = await run_command_safely(
        console, f"use {full_module_path}", 
        execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
    )
    
    has_error, error_msg = check_console_error(use_output)
    if has_error:
        return create_error_response(f"Failed to load module: {error_msg}", full_module_path)
    
    # Set module options
    for key, value in module_options.items():
        val_str = str(value)
        if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
            import shlex
            val_str = shlex.quote(val_str)
        elif isinstance(value, bool):
            val_str = str(value).lower()
        
        cmd = f"set {key} {val_str}"
        setup_output = await run_command_safely(
            console, cmd, execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
        )
        
        has_error, error_msg = check_console_error(setup_output)
        if has_error:
            return create_error_response(f"Error setting option {key}: {error_msg}", full_module_path)
    
    # Set payload if specified
    if payload_spec:
        payload_result = await _setup_payload_in_console(console, payload_spec)
        if payload_result["status"] != "success":
            return payload_result
    
    return create_success_response("Module setup completed")


async def _setup_payload_in_console(
    console: Any,
    payload_spec: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Setup payload in console.
    
    Args:
        console: The console object
        payload_spec: Payload specification
        
    Returns:
        Setup result dictionary
    """
    payload_name = payload_spec.get('name')
    payload_options = payload_spec.get('options', {})
    
    if not payload_name:
        return create_error_response("Payload name not specified")
    
    # Set payload
    payload_base_name = normalize_payload_name(payload_name)
    payload_output = await run_command_safely(
        console, f"set PAYLOAD {payload_base_name}",
        execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
    )
    
    has_error, error_msg = check_console_error(payload_output)
    if has_error:
        return create_error_response(f"Failed to set payload: {error_msg}")
    
    # Set payload options
    for key, value in payload_options.items():
        val_str = str(value)
        if isinstance(value, str) and any(c in val_str for c in [' ', '"', "'", '\\']):
            import shlex
            val_str = shlex.quote(val_str)
        elif isinstance(value, bool):
            val_str = str(value).lower()
        
        cmd = f"set {key} {val_str}"
        setup_output = await run_command_safely(
            console, cmd, execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
        )
        
        has_error, error_msg = check_console_error(setup_output)
        if has_error:
            return create_error_response(f"Error setting payload option {key}: {error_msg}")
    
    return create_success_response("Payload setup completed")


async def _execute_command_in_console(
    console: Any,
    command: str,
    timeout: int
) -> Dict[str, Any]:
    """
    Execute a command in console.
    
    Args:
        console: The console object
        command: Command to execute
        timeout: Timeout in seconds
        
    Returns:
        Execution result dictionary
    """
    # Clear any existing output before executing the command
    await asyncio.sleep(0.1)  # Small delay to ensure console is ready
    try:
        # Read and discard any existing output to clear the buffer
        await asyncio.to_thread(lambda: console.read())
    except Exception:
        pass  # Ignore errors when clearing buffer
    
    # Execute the command and capture only its output
    module_output = await run_command_safely(
        console, command, execution_timeout=timeout
    )
    
    # Parse the output for session information
    session_id = _extract_session_id_from_output(module_output)
    
    return {
        "status": "success",
        "module_output": module_output,
        "session_id": session_id
    }


def _extract_session_id_from_output(output: str) -> Optional[int]:
    """
    Extract session ID from module output.
    
    Args:
        output: The module output
        
    Returns:
        Session ID if found, None otherwise
    """
    import re
    
    # Look for session opened messages
    session_patterns = [
        r"Session (\d+) opened",
        r"meterpreter session (\d+) opened",
        r"Command shell session (\d+) opened"
    ]
    
    for pattern in session_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                continue
    
    return None


async def show_module_options_via_console(
    module_name: str,
    module_type: str = "exploit",
    payload_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Show module options via console to get formatted output.
    
    Args:
        module_name: Name/path of the module
        module_type: Type of module
        payload_name: Optional payload name
        
    Returns:
        Dictionary with formatted options output
    """
    full_module_path = normalize_module_path(module_name, module_type)
    
    async with get_msf_console() as console:
        try:
            # Use the module
            use_output = await run_command_safely(
                console, f"use {full_module_path}",
                execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
            )
            
            has_error, error_msg = check_console_error(use_output)
            if has_error:
                return create_error_response(f"Failed to load module: {error_msg}", full_module_path)
            
            # Set payload if specified
            if payload_name:
                payload_base_name = normalize_payload_name(payload_name)
                payload_output = await run_command_safely(
                    console, f"set PAYLOAD {payload_base_name}",
                    execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
                )
                
                has_error, error_msg = check_console_error(payload_output)
                if has_error:
                    return create_error_response(f"Failed to set payload: {error_msg}")
            
            # Get the formatted options output
            options_output = await run_command_safely(
                console, "show options",
                execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
            )
            
            has_error, error_msg = check_console_error(options_output)
            if has_error:
                return create_error_response(f"Failed to get options: {error_msg}")
            
            return format_options_output(full_module_path, payload_name, options_output)
            
        except Exception as e:
            logger.exception(f"Unexpected error getting options for '{module_name}'")
            return create_error_response(f"Unexpected error: {e}")


async def execute_module_console(
    module_type: str,
    module_name: str,
    module_options: Dict[str, Any],
    command: str,
    payload_spec: Optional[Dict[str, Any]] = None,
    timeout: int = 60
) -> Dict[str, Any]:
    """
    Execute a module synchronously via console with proper error handling.
    
    Args:
        module_type: Type of module ('exploit', 'auxiliary', 'post')
        module_name: Name/path of the module
        module_options: Dictionary of module options
        command: Command to execute ('exploit', 'run', 'check')
        payload_spec: Optional payload specification
        timeout: Timeout in seconds
        
    Returns:
        Dictionary with execution results or error details
    """
    from console_utils import get_msf_console, run_command_safely, DEFAULT_CONSOLE_READ_TIMEOUT
    
    # Normalize module path
    full_module_path = normalize_module_path(module_name, module_type)
    
    logger.info(f"Executing {full_module_path} synchronously via console (command: {command})...")
    
    async with get_msf_console() as console:
        try:
            # Setup module
            setup_result = await _setup_module_in_console(console, full_module_path, module_options)
            if setup_result.get("status") == "error":
                return setup_result
            
            # Setup payload if provided
            if payload_spec:
                payload_result = await _setup_payload_in_console(console, payload_spec)
                if payload_result.get("status") == "error":
                    return payload_result
            
            # Execute the command
            result = await _execute_command_in_console(console, command, timeout)
            return result
            
        except Exception as e:
            logger.exception(f"Unexpected error executing {full_module_path}")
            return create_error_response(f"Unexpected error: {e}")


async def execute_module_rpc(
    module_type: str,
    module_name: str,
    module_options: Dict[str, Any],
    payload_spec: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Execute a module as a background job via RPC.
    
    Args:
        module_type: Type of module ('exploit', 'auxiliary', 'post')
        module_name: Name/path of the module
        module_options: Dictionary of module options
        payload_spec: Optional payload specification
        
    Returns:
        Dictionary with job results or error details
    """
    from console_utils import get_msf_client
    from pymetasploit3.msfrpc import MsfRpcError
    
    client = get_msf_client()
    
    try:
        # Get module object
        module_obj = await _get_module_object_rpc(client, module_type, module_name)
        full_module_path = getattr(module_obj, 'fullname', f"{module_type}/{module_name}")
        
        # Set module options
        await _set_module_options_rpc(module_obj, module_options)
        
        # Prepare payload if needed
        payload_obj_to_pass = None
        if module_type == 'exploit' and payload_spec:
            payload_result = await _prepare_payload_rpc(client, payload_spec)
            if isinstance(payload_result, dict) and payload_result.get("status") == "error":
                return payload_result
            payload_obj_to_pass = payload_result
        
        # Execute module
        logger.info(f"Executing module {full_module_path} as background job via RPC...")
        if module_type == 'exploit':
            exec_result = await asyncio.to_thread(lambda: module_obj.execute(payload=payload_obj_to_pass))
        else:
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())
        
        if exec_result and 'job_id' in exec_result:
            job_id = exec_result['job_id']
            logger.info(f"Module {full_module_path} started as job {job_id}")
            return create_success_response({
                "job_id": job_id,
                "module": full_module_path,
                "message": f"Module started as background job {job_id}"
            })
        else:
            return create_error_response(f"Failed to start module {full_module_path}")
            
    except Exception as e:
        logger.exception(f"Error executing module {module_name} via RPC")
        return create_error_response(f"RPC execution failed: {e}")


async def _get_module_object_rpc(client, module_type: str, module_name: str):
    """Get module object via RPC."""
    from utils import normalize_module_path
    
    full_module_path = normalize_module_path(module_name, module_type)
    
    try:
        # Use client.modules.use() method instead of dictionary indexing
        # Extract the base module name (without the module type prefix)
        if '/' in full_module_path:
            base_module_name = full_module_path.split('/', 1)[1]
        else:
            base_module_name = full_module_path
            
        module_obj = await asyncio.to_thread(lambda: client.modules.use(module_type, base_module_name))
        return module_obj
    except Exception as e:
        raise ValueError(f"Module '{full_module_path}' not found: {e}")


async def _set_module_options_rpc(module_obj, module_options: Dict[str, Any]):
    """Set module options via RPC."""
    from pymetasploit3.msfrpc import MsfRpcError
    
    for key, value in module_options.items():
        try:
            await asyncio.to_thread(lambda: module_obj.__setitem__(key, value))
        except (MsfRpcError, KeyError, TypeError) as e:
            error_msg = str(e)
            if "Invalid option" in error_msg:
                # Try to get available options for better error message
                try:
                    available_options = await asyncio.to_thread(lambda: list(module_obj.options.keys()))
                    options_info = f"Available options: {', '.join(sorted(available_options))}" if available_options else "No options available"
                    raise ValueError(f"Invalid option '{key}'. {options_info}")
                except Exception:
                    raise ValueError(f"Invalid option '{key}': {error_msg}")
            else:
                raise ValueError(f"Error setting option '{key}': {error_msg}")


async def _prepare_payload_rpc(client, payload_spec: Dict[str, Any]) -> Any:
    """Prepare payload object via RPC."""
    from pymetasploit3.msfrpc import MsfRpcError
    
    payload_name = payload_spec.get('name')
    payload_options = payload_spec.get('options', {})
    
    if not payload_name:
        return create_error_response("Payload name not specified")
    
    try:
        # Use client.modules.use() method for payloads as well
        payload_obj = await asyncio.to_thread(lambda: client.modules.use('payload', payload_name))
        await _set_module_options_rpc(payload_obj, payload_options)
        return payload_obj
    except Exception as e:
        return create_error_response(f"Failed to prepare payload '{payload_name}': {e}")
