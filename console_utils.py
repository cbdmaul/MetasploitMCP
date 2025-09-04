# -*- coding: utf-8 -*-
"""
Console utility functions for MetasploitMCP.
These are low-level console operations that don't depend on the main MCP module.
"""

import asyncio
import contextlib
import logging
import re
from typing import Optional

from pymetasploit3.msfrpc import MsfConsole, MsfRpcClient, MsfRpcError

logger = logging.getLogger(__name__)

# Console timeout constants
DEFAULT_CONSOLE_READ_TIMEOUT = 15  # Default for quick console commands
LONG_CONSOLE_READ_TIMEOUT = 300    # For long-running commands like exploits
SESSION_READ_INACTIVITY_TIMEOUT = 10  # seconds of inactivity before assuming complete

# MSF prompt detection regex
MSF_PROMPT_RE = re.compile(rb'msf\d+\s+.*>\s*$', re.MULTILINE)

# Global MSF client - will be initialized by the main module
_msf_client_instance: Optional[MsfRpcClient] = None

def set_msf_client(client: MsfRpcClient) -> None:
    """Set the global MSF client. Called by the main module during initialization."""
    global _msf_client_instance
    _msf_client_instance = client

def get_msf_client() -> MsfRpcClient:
    """Get the global MSF client."""
    if _msf_client_instance is None:
        raise ConnectionError("MSF client not initialized. Call initialize_msf_connection() first.")
    return _msf_client_instance

@contextlib.asynccontextmanager
async def get_msf_console() -> MsfConsole:
    """
    Async context manager for creating and reliably destroying an MSF console.
    """
    client = get_msf_client() # Raises ConnectionError if not initialized
    console_object: Optional[MsfConsole] = None
    console_id_str: Optional[str] = None
    try:
        logger.debug("Creating temporary MSF console...")
        # Create console object directly
        console_object = await asyncio.to_thread(lambda: client.consoles.console())

        # Get ID using .cid attribute
        if isinstance(console_object, MsfConsole) and hasattr(console_object, 'cid'):
            console_id_val = getattr(console_object, 'cid')
            console_id_str = str(console_id_val) if console_id_val is not None else None
            if not console_id_str:
                raise ValueError("Console object created, but .cid attribute is empty or None.")
            logger.info(f"MSF console created (ID: {console_id_str})")

            # Read initial prompt/banner to clear buffer and ensure readiness
            await asyncio.sleep(0.2) # Short delay for prompt to appear
            initial_read = await asyncio.to_thread(lambda: console_object.read())
            logger.debug(f"Initial console read (clearing buffer): {initial_read}")
            yield console_object # Yield the ready console object
        else:
            # This case should ideally not happen if .console() works as expected
            logger.error(f"client.consoles.console() did not return expected MsfConsole object with .cid. Got type: {type(console_object)}")
            raise MsfRpcError(f"Unexpected result from console creation: {console_object}")

    except MsfRpcError as e:
        logger.error(f"MsfRpcError during console operation: {e}")
        raise MsfRpcError(f"Error creating/accessing MSF console: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during console creation/setup")
        raise RuntimeError(f"Unexpected error during console operation: {e}") from e
    finally:
        # Destruction Logic
        if console_id_str and _msf_client_instance: # Check client still exists
            try:
                logger.info(f"Attempting to destroy Metasploit console (ID: {console_id_str})...")
                # Use lambda to avoid potential issues with capture
                destroy_result = await asyncio.to_thread(
                    lambda cid=console_id_str: _msf_client_instance.consoles.destroy(cid)
                )
                logger.debug(f"Console destroy result: {destroy_result}")
            except Exception as e:
                # Log error but don't raise exception during cleanup
                logger.error(f"Error destroying MSF console {console_id_str}: {e}")
        elif console_object and not console_id_str:
             logger.warning("Console object created but no valid ID obtained, cannot explicitly destroy.")
        # else: logger.debug("No console ID obtained, skipping destruction.")

async def run_command_safely(console: MsfConsole, cmd: str, execution_timeout: Optional[int] = None) -> str:
    """
    Safely run a command on a Metasploit console and return the output.
    Relies primarily on detecting the MSF prompt for command completion.

    Args:
        console: The Metasploit console object (MsfConsole).
        cmd: The command to run.
        execution_timeout: Optional specific timeout for this command's execution phase.

    Returns:
        The command output as a string.
    """
    if not (hasattr(console, 'write') and hasattr(console, 'read')):
        logger.error(f"Console object {type(console)} lacks required methods (write, read).")
        raise TypeError("Unsupported console object type for command execution.")
    
    # Clear out the console read buffer
    prev_buffer = await asyncio.to_thread(lambda: console.read())
    if len(prev_buffer) > 0:
        logger.debug(f"Previous buffer: {prev_buffer}")

    try:
        logger.debug(f"Running console command: {cmd}")
        write_start_time = asyncio.get_event_loop().time()
        await asyncio.to_thread(lambda: console.write(cmd + '\n'))
        write_duration = asyncio.get_event_loop().time() - write_start_time
        logger.debug(f"Console write completed for '{cmd}' in {write_duration:.3f}s")

        # For "set" commands, don't wait for console output as they produce none
        if cmd.strip().startswith("set "):
            logger.debug(f"Skipping console output wait for 'set' command: {cmd}")
            # Actually, let's wait a bit and check for errors
            await asyncio.sleep(1)
            try:
                quick_read = await asyncio.to_thread(lambda: console.read())
                if quick_read and any(err in quick_read for err in ["[-] Error", "Invalid option", "Unknown option"]):
                    logger.error(f"Error detected in set command '{cmd}': {quick_read}")
                    return quick_read
            except Exception as e:
                logger.debug(f"Quick read after set command failed: {e}")
            return ""

        output_buffer = b"" # Read as bytes to handle potential encoding issues and prompt matching
        start_time = asyncio.get_event_loop().time()

        # Determine read timeout - use inactivity timeout as fallback
        read_timeout = execution_timeout or (LONG_CONSOLE_READ_TIMEOUT if cmd.strip().startswith(("run", "exploit", "check")) else DEFAULT_CONSOLE_READ_TIMEOUT)
        check_interval = 0.1 # Seconds between reads
        last_data_time = start_time

        # Progress tracking for long-running commands
        progress_interval = 10  # Log progress every 10 seconds
        last_progress_time = start_time
        total_chunks_read = 0
        total_bytes_read = 0
        timed_out = False  # Track if we exit due to timeout
        
        logger.info(f"Starting console command execution: '{cmd}' (timeout: {read_timeout}s)")
        
        while True:
            await asyncio.sleep(check_interval)
            current_time = asyncio.get_event_loop().time()
            elapsed_time = current_time - start_time

            # Progress logging for long-running operations
            if (current_time - last_progress_time) >= progress_interval:
                logger.info(f"Console command '{cmd}' still running... "
                          f"Elapsed: {elapsed_time:.1f}s/{read_timeout}s, "
                          f"Chunks read: {total_chunks_read}, "
                          f"Bytes received: {total_bytes_read}, "
                          f"Last activity: {current_time - last_data_time:.1f}s ago")
                last_progress_time = current_time

            # Check overall timeout first
            if elapsed_time > read_timeout:
                 logger.warning(f"Overall timeout ({read_timeout}s) reached for console command '{cmd}'. "
                              f"Total chunks: {total_chunks_read}, bytes: {total_bytes_read}")
                 timed_out = True
                 break

            # Read available data
            try:
                chunk_result = await asyncio.to_thread(lambda: console.read())
                # console.read() returns {'data': '...', 'prompt': '...', 'busy': bool}
                chunk_data = chunk_result.get('data', '').encode('utf-8', errors='replace') # Ensure bytes
                is_busy = chunk_result.get('busy', False)

                # Handle the prompt - ensure it's bytes for pattern matching
                prompt_str = chunk_result.get('prompt', '')
                prompt_bytes = prompt_str.encode('utf-8', errors='replace') if isinstance(prompt_str, str) else prompt_str
                
                # Enhanced debug logging for timeout analysis
                if chunk_data or is_busy or prompt_str:
                    logger.debug(f"Console read result for '{cmd}' at {elapsed_time:.1f}s: "
                               f"data_len={len(chunk_data)}, busy={is_busy}, prompt='{prompt_str[:50]}...' if len(prompt_str) > 50 else prompt_str")
                
                # Log console busy state periodically
                if is_busy and (current_time - last_progress_time) >= (progress_interval - 1):
                    logger.debug(f"Console reports busy=True for command '{cmd}' at {elapsed_time:.1f}s")

                    
            except Exception as read_err:
                logger.warning(f"Error reading from console during command '{cmd}' at {elapsed_time:.1f}s: {read_err}")
                await asyncio.sleep(0.5) # Wait a bit before retrying or timing out
                continue

            if chunk_data:
                chunk_size = len(chunk_data)
                total_chunks_read += 1
                total_bytes_read += chunk_size
                
                # Log first data received
                if total_chunks_read == 1:
                    logger.debug(f"First data received for '{cmd}' after {elapsed_time:.3f}s: {chunk_size} bytes")
                
                # Log significant data chunks
                if chunk_size > 100:
                    logger.debug(f"Received significant data chunk for '{cmd}': {chunk_size} bytes "
                               f"(total: {total_bytes_read} bytes in {total_chunks_read} chunks)")
                
                output_buffer += chunk_data
                last_data_time = current_time # Reset inactivity timer

                if is_busy and elapsed_time <= execution_timeout:
                    continue

                # For exploit/run commands, look for completion indicators in the output
                if cmd.strip() in ['exploit', 'run']:
                    output_text = output_buffer.decode('utf-8', errors='replace')
                    # Check for exploit completion indicators
                    if any(indicator in output_text.lower() for indicator in 
                          ['session opened', 'exploit completed', 'exploit failed', 'run failed',
                           'command shell session', 'meterpreter session', 'connection refused', 'connection reset',
                           'target appears to be down', 'no connection could be made', 'timed out']):
                        logger.info(f"Detected exploit completion indicator for '{cmd}' after {elapsed_time:.1f}s. Command complete.")
                        break
                    # For exploit commands, be more conservative about prompt detection
                    # Only consider it complete if we have substantial output AND the prompt
                    elif (prompt_bytes and MSF_PROMPT_RE.search(prompt_bytes) and 
                          len(output_text) > 200 and elapsed_time > 5.0):
                        logger.info(f"Detected MSF prompt with substantial output for '{cmd}' after {elapsed_time:.1f}s. Command complete.")
                        break
                else:
                    # For other commands, use the original prompt detection logic
                    if prompt_bytes and MSF_PROMPT_RE.search(prompt_bytes):
                         logger.info(f"Detected MSF prompt in console.read() result for '{cmd}' after {elapsed_time:.1f}s. Command complete.")
                         break
                    # Secondary Check: Does the buffered output end with the prompt?
                    # Needed if prompt wasn't in the last read chunk but arrived earlier.
                    if MSF_PROMPT_RE.search(output_buffer):
                         logger.info(f"Detected MSF prompt at end of buffer for '{cmd}' after {elapsed_time:.1f}s. Command complete.")
                         break

            # Fallback Completion Check: Inactivity timeout
            elif (current_time - last_data_time) > SESSION_READ_INACTIVITY_TIMEOUT:
                inactivity_duration = current_time - last_data_time
                logger.info(f"Console inactivity timeout ({SESSION_READ_INACTIVITY_TIMEOUT}s) reached for command '{cmd}' "
                          f"after {elapsed_time:.1f}s total. No data for {inactivity_duration:.1f}s. Assuming complete.")
                break

        # Decode the final buffer
        final_output = output_buffer.decode('utf-8', errors='replace').strip()
        total_execution_time = asyncio.get_event_loop().time() - start_time
        
        # Handle timeout vs normal completion
        if timed_out:
            logger.error(f"Console command '{cmd}' TIMED OUT after {total_execution_time:.1f}s (limit: {read_timeout}s). "
                        f"Read {total_chunks_read} chunks, {total_bytes_read} bytes, "
                        f"output length: {len(final_output)} chars")
            logger.debug(f"Timeout output for '{cmd}' (length {len(final_output)}):\n{final_output[:500]}{'...' if len(final_output) > 500 else ''}")
            return f"TIMEOUT_ERROR: Command '{cmd}' exceeded {read_timeout}s timeout after {total_execution_time:.1f}s. Output: {final_output}"
        else:
            logger.info(f"Console command '{cmd}' completed successfully in {total_execution_time:.1f}s. "
                       f"Read {total_chunks_read} chunks, {total_bytes_read} bytes, "
                       f"output length: {len(final_output)} chars")
            logger.debug(f"Final output for '{cmd}' (length {len(final_output)}):\n{final_output[:500]}{'...' if len(final_output) > 500 else ''}")
            return final_output

    except Exception as e:
        elapsed_time = asyncio.get_event_loop().time() - start_time
        logger.exception(f"Error executing console command '{cmd}' after {elapsed_time:.1f}s. "
                        f"Chunks read: {total_chunks_read}, bytes: {total_bytes_read}")
        raise RuntimeError(f"Failed executing console command '{cmd}' after {elapsed_time:.1f}s: {e}") from e
