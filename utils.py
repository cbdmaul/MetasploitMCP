# -*- coding: utf-8 -*-
"""
Utility functions for MetasploitMCP to reduce code duplication and improve maintainability.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


def normalize_module_path(module_name: str, module_type: str) -> str:
    """
    Normalize a module name to a full path.
    
    Args:
        module_name: The module name (e.g., 'unix/ftp/vsftpd_234_backdoor' or 'vsftpd_234_backdoor')
        module_type: The module type ('exploit', 'auxiliary', 'post', 'payload')
        
    Returns:
        The normalized full module path
    """
    if '/' not in module_name:
        return f"{module_type}/{module_name}"
    else:
        if not module_name.startswith(module_type + '/'):
            if not any(module_name.startswith(pfx + '/') for pfx in ['exploit', 'payload', 'post', 'auxiliary', 'encoder', 'nop']):
                return f"{module_type}/{module_name}"
            else:
                return module_name
        else:
            return module_name


def normalize_payload_name(payload_name: str) -> str:
    """
    Normalize a payload name for use in 'set PAYLOAD' command.
    
    Args:
        payload_name: The payload name (e.g., 'linux/x86/meterpreter/reverse_tcp' or 'payload/linux/x86/meterpreter/reverse_tcp')
        
    Returns:
        The normalized payload name for console commands
    """
    if '/' in payload_name:
        parts = payload_name.split('/')
        if parts[0] == 'payload':
            return '/'.join(parts[1:])
        else:
            return payload_name
    else:
        return payload_name


def get_module_fullname(module_obj: Any, module_type: str, module_name: str) -> str:
    """
    Get the full name of a module object.
    
    Args:
        module_obj: The module object
        module_type: The module type
        module_name: The original module name
        
    Returns:
        The full module name
    """
    return getattr(module_obj, 'fullname', f"{module_type}/{module_name}")


async def safe_rpc_call(func, *args, timeout: float = 30.0, **kwargs) -> Any:
    """
    Safely execute an RPC call with timeout and error handling.
    
    Args:
        func: The function to call
        *args: Positional arguments for the function
        timeout: Timeout in seconds
        **kwargs: Keyword arguments for the function
        
    Returns:
        The result of the function call
        
    Raises:
        asyncio.TimeoutError: If the call times out
        Exception: If the function call fails
    """
    return await asyncio.wait_for(
        asyncio.to_thread(func, *args, **kwargs),
        timeout=timeout
    )


def check_console_error(output: str, error_patterns: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Check if console output contains error patterns.
    
    Args:
        output: The console output to check
        error_patterns: List of error patterns to check for (defaults to common error patterns)
        
    Returns:
        Tuple of (has_error, error_message)
    """
    if error_patterns is None:
        error_patterns = ["[-] Error", "Unknown module", "Failed to load", "Invalid option", "Unknown option", "No module selected"]
    
    for pattern in error_patterns:
        if pattern in output:
            return True, f"Error detected: {pattern}"
    
    return False, ""


def format_options_output(module_name: str, payload_name: Optional[str], options_output: str) -> Dict[str, Any]:
    """
    Format the options output into a structured response.
    
    Args:
        module_name: The module name
        payload_name: The payload name (if any)
        options_output: The raw options output from console
        
    Returns:
        Formatted response dictionary
    """
    return {
        "status": "success",
        "formatted_output": options_output,
        "module_name": module_name,
        "payload_name": payload_name
    }


def create_error_response(message: str, module_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a standardized error response.
    
    Args:
        message: The error message
        module_name: Optional module name for context
        
    Returns:
        Error response dictionary
    """
    response = {"status": "error", "message": message}
    if module_name:
        response["module"] = module_name
    return response


def create_success_response(message: str, **kwargs) -> Dict[str, Any]:
    """
    Create a standardized success response.
    
    Args:
        message: The success message
        **kwargs: Additional fields to include in the response
        
    Returns:
        Success response dictionary
    """
    response = {"status": "success", "message": message}
    response.update(kwargs)
    return response


def validate_session_id(session_id: int) -> Tuple[bool, str]:
    """
    Validate a session ID.
    
    Args:
        session_id: The session ID to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(session_id, int) or session_id < 0:
        return False, "Session ID must be a non-negative integer"
    return True, ""


def validate_job_id(job_id: int) -> Tuple[bool, str]:
    """
    Validate a job ID.
    
    Args:
        job_id: The job ID to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(job_id, int) or job_id < 0:
        return False, "Job ID must be a non-negative integer"
    return True, ""


def extract_module_info_from_output(output: str) -> Dict[str, Any]:
    """
    Extract module information from console output.
    
    Args:
        output: Console output containing module information
        
    Returns:
        Dictionary with extracted module information
    """
    info = {}
    
    # Extract module name from prompts like "msf6 exploit(unix/ftp/vsftpd_234_backdoor) >"
    import re
    prompt_match = re.search(r'msf6\s+(\w+)\(([^)]+)\)', output)
    if prompt_match:
        info['module_type'] = prompt_match.group(1)
        info['module_name'] = prompt_match.group(2)
    
    return info


def parse_options_from_formatted_output(formatted_output: str) -> Dict[str, Any]:
    """
    Parse options from formatted console output.
    
    Args:
        formatted_output: The formatted options output from console
        
    Returns:
        Dictionary with parsed options information
    """
    import re
    
    result = {
        "module_options": {},
        "payload_options": {},
        "exploit_targets": []
    }
    
    # Split into sections
    sections = formatted_output.split('\n\n')
    
    current_section = None
    for section in sections:
        if 'Module options' in section:
            current_section = 'module'
            # Extract module name
            module_match = re.search(r'Module options \(([^)]+)\)', section)
            if module_match:
                result['module_options']['module_name'] = module_match.group(1)
        elif 'Payload options' in section:
            current_section = 'payload'
            # Extract payload name
            payload_match = re.search(r'Payload options \(([^)]+)\)', section)
            if payload_match:
                result['payload_options']['payload_name'] = payload_match.group(1)
        elif 'Exploit target' in section:
            current_section = 'targets'
    
    return result


def parse_options_gracefully(options: Union[Dict[str, Any], str, None]) -> Dict[str, Any]:
    """
    Gracefully parse options from different formats.
    
    Handles:
    - Dict format (correct): {"key": "value", "key2": "value2"}
    - String format (common mistake): "key=value,key=value"
    - None: returns empty dict
    
    Args:
        options: Options in dict format, string format, or None
        
    Returns:
        Dictionary of parsed options
        
    Raises:
        ValueError: If string format is malformed
    """
    import logging
    logger = logging.getLogger(__name__)
    
    if options is None:
        return {}
    
    if isinstance(options, dict):
        # Already correct format
        return options
    
    if isinstance(options, str):
        # Handle the common mistake format: "key=value,key=value"
        if not options.strip():
            return {}
            
        logger.info(f"Converting string format options to dict: {options}")
        parsed_options = {}
        
        try:
            # Split by comma and then by equals
            pairs = [pair.strip() for pair in options.split(',') if pair.strip()]
            for pair in pairs:
                if '=' not in pair:
                    raise ValueError(f"Invalid option format: '{pair}' (missing '=')")
                
                key, value = pair.split('=', 1)  # Split only on first '='
                key = key.strip()
                value = value.strip()
                
                # Validate key is not empty
                if not key:
                    raise ValueError(f"Invalid option format: '{pair}' (empty key)")
                
                # Remove quotes if they wrap the entire value
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                # Basic type conversion
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    try:
                        value = int(value)
                    except ValueError:
                        pass  # Keep as string if conversion fails
                
                parsed_options[key] = value
            
            logger.info(f"Successfully converted string options to dict: {parsed_options}")
            return parsed_options
            
        except Exception as e:
            raise ValueError(f"Failed to parse options string '{options}': {e}. Expected format: 'key=value,key2=value2' or dict {{'key': 'value'}}")
    
    raise ValueError(f"Invalid options type: {type(options)}. Expected dict, string, or None.")
