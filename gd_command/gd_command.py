#!/usr/bin/env python3
"""
rclone_wrapper.py - A wrapper script to monitor rclone/gclone transfer progress
with max-transfer limit support.

Usage:
    python3 rclone_wrapper.py -shell "<command>" --max-transfer <xxUnit>
"""

import argparse
import subprocess
import sys
import os
import re
import platform
from typing import Optional, Dict, Any


def setup_utf8_encoding():
    """Set up UTF-8 encoding for different platforms and shells."""
    system = platform.system().lower()
    
    if system == "windows":
        # Check if running in PowerShell or CMD
        parent_process = os.environ.get('PSModulePath')
        if parent_process:  # PowerShell
            try:
                subprocess.run([
                    'powershell', '-Command', 
                    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8'
                ], check=False, capture_output=True)
            except:
                pass
        else:  # CMD
            try:
                subprocess.run(['chcp', '65001'], check=False, capture_output=True)
            except:
                pass


def parse_size_to_bytes(size_str: str) -> int:
    """Convert size string like '1.195 TiB' to bytes."""
    if not size_str:
        return 0
    
    # Remove any extra whitespace
    size_str = size_str.strip()
    
    # Define conversion factors (including both binary and decimal units)
    units = {
        'B': 1,
        'KiB': 1024,
        'MiB': 1024 ** 2,
        'GiB': 1024 ** 3,
        'TiB': 1024 ** 4,
        'PiB': 1024 ** 5,
        'KB': 1000,
        'MB': 1000 ** 2,
        'GB': 1000 ** 3,
        'TB': 1000 ** 4,
        'PB': 1000 ** 5,
    }
    
    # Extract number and unit - more flexible regex
    match = re.match(r'([0-9.]+)\s*([A-Za-z]*)', size_str)
    if not match:
        return 0
    
    try:
        value = float(match.group(1))
        unit = match.group(2).strip()
        
        # If no unit specified, assume bytes
        if not unit:
            unit = 'B'
            
        if unit in units:
            return int(value * units[unit])
    except (ValueError, IndexError):
        pass
    
    return 0


def extract_transferred_amount(line: str) -> Optional[str]:
    """Extract the transferred amount from Transferred line."""
    # Updated regex to handle various formats including "0 B"
    match = re.search(r'Transferred:\s+([0-9.]+\s*[A-Za-z]*)', line)
    if match:
        return match.group(1).strip()
    return None


def is_progress_line(line: str) -> bool:
    """Check if line contains progress information we want to display."""
    patterns = [
        r'Transferred:\s+.*',
        r'Errors:\s+.*',
        r'Elapsed time:\s+.*'
    ]
    
    for pattern in patterns:
        if re.search(pattern, line):
            return True
    return False


def safe_decode(data: bytes) -> str:
    """Safely decode bytes to string with fallback encodings."""
    encodings = ['utf-8', 'utf-8', 'latin-1']
    
    for i, encoding in enumerate(encodings):
        try:
            if i == 1:  # Second attempt with utf-8, use ignore
                return data.decode(encoding, errors='ignore')
            else:
                return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    
    # Last resort - replace bad characters
    return data.decode('utf-8', errors='replace')


def run_command_with_monitoring(command: str, max_transfer_bytes: int = 0) -> int:
    """
    Run command and monitor its output with optional transfer limit.
    Returns the exit code of the command.
    """
    try:
        # Start the process
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=False
        )
        
        line_buffer = b''
        current_line = ''
        
        while True:
            byte = process.stdout.read(1)
            if not byte:
                # Process finished, handle any remaining buffer
                if line_buffer.strip():
                    line = safe_decode(line_buffer.strip())
                    print(line)
                break
                
            line_buffer += byte
            
            # Handle both \r (carriage return) and \n (newline)
            if byte == b'\n':
                # Complete line with newline
                if line_buffer.strip():
                    line = safe_decode(line_buffer.strip())
                    
                    # Check if this is a progress line we want to monitor
                    if is_progress_line(line):
                        print(line)
                        
                        # Check transfer limit
                        if max_transfer_bytes > 0:
                            transferred_str = extract_transferred_amount(line)
                            if transferred_str:
                                current_bytes = parse_size_to_bytes(transferred_str)
                                print(f"DEBUG: Transferred '{transferred_str}' = {current_bytes} bytes, limit = {max_transfer_bytes} bytes", file=sys.stderr)
                                if current_bytes >= max_transfer_bytes:
                                    print(f"\nMax transfer limit reached: {transferred_str}")
                                    process.terminate()
                                    return 1
                    else:
                        # Print non-progress lines as-is
                        print(line)
                
                line_buffer = b''
                
            elif byte == b'\r':
                # Handle carriage return (progress updates)
                if line_buffer.strip():
                    line = safe_decode(line_buffer.strip())
                    
                    # For progress lines, overwrite the current line
                    if is_progress_line(line):
                        # Clear current line and print new progress
                        sys.stdout.write('\r' + ' ' * 100 + '\r')  # Clear line
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        
                        # Check transfer limit
                        if max_transfer_bytes > 0:
                            transferred_str = extract_transferred_amount(line)
                            if transferred_str:
                                current_bytes = parse_size_to_bytes(transferred_str)
                                print(f"\nDEBUG: Transferred '{transferred_str}' = {current_bytes} bytes, limit = {max_transfer_bytes} bytes", file=sys.stderr)
                                if current_bytes >= max_transfer_bytes:
                                    print(f"\nMax transfer limit reached: {transferred_str}")
                                    process.terminate()
                                    return 1
                    else:
                        print(line)
                
                line_buffer = b''
        
        # Wait for process to complete
        return_code = process.wait()
        return return_code
        
    except KeyboardInterrupt:
        if 'process' in locals():
            process.terminate()
        return 130
    except Exception as e:
        print(f"Error running command: {e}", file=sys.stderr)
        return 1


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Wrapper script for rclone/gclone with transfer monitoring'
    )
    parser.add_argument(
        '-shell', 
        required=True,
        help='The command to execute (e.g., "rclone copy source dest -P")'
    )
    parser.add_argument(
        '--max-transfer',
        help='Maximum transfer amount (e.g., "1.5TiB", "500GiB")'
    )
    
    args = parser.parse_args()
    
    # Setup UTF-8 encoding
    setup_utf8_encoding()
    
    # Parse max transfer limit
    max_transfer_bytes = 0
    if args.max_transfer:
        max_transfer_bytes = parse_size_to_bytes(args.max_transfer)
        if max_transfer_bytes <= 0:
            print(f"Invalid max-transfer value: {args.max_transfer}", file=sys.stderr)
            return 1
    
    # Run the command with monitoring
    return_code = run_command_with_monitoring(args.shell, max_transfer_bytes)
    
    return return_code


if __name__ == '__main__':
    sys.exit(main())