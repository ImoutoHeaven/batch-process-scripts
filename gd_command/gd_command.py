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
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any


class TransferTracker:
    """Tracks daily transfer amounts within UTC date windows."""
    
    def __init__(self):
        self.current_utc_date = None
        self.daily_baseline = 0
    
    def get_daily_transferred(self, current_transferred_bytes: int) -> int:
        """
        Calculate actual daily transferred amount, handling UTC date changes.
        Returns the amount transferred within the current UTC date window.
        """
        today_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        
        if self.current_utc_date is None:
            # First initialization
            self.current_utc_date = today_utc
            self.daily_baseline = current_transferred_bytes
            print(f"DEBUG: Initialized transfer tracker for UTC date {today_utc}, baseline = {current_transferred_bytes} bytes", file=sys.stderr)
            return 0  # No transfer counted yet on first initialization
        
        if self.current_utc_date != today_utc:
            # Detected UTC date change (crossed UTC 00:00)
            print(f"DEBUG: Detected UTC date change: {self.current_utc_date} -> {today_utc}", file=sys.stderr)
            print(f"DEBUG: Resetting daily transfer tracking, new baseline = {current_transferred_bytes} bytes", file=sys.stderr)
            
            self.current_utc_date = today_utc
            self.daily_baseline = current_transferred_bytes
            return 0  # Reset to 0 for new day
        
        # Calculate daily transferred amount
        daily_transferred = current_transferred_bytes - self.daily_baseline
        return max(0, daily_transferred)  # Ensure non-negative


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
    # Only match lines with storage units (B, KiB, MiB, GiB, TiB, etc.)
    # This excludes file count lines like "Transferred:            4 / 702, 1%"
    match = re.search(r'Transferred:\s+([0-9.]+\s*(?:B|KiB|MiB|GiB|TiB|PiB|KB|MB|GB|TB|PB))\s*/', line)
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


def calculate_seconds_until_utc_midnight() -> int:
    """Calculate seconds until next UTC midnight."""
    now_utc = datetime.now(timezone.utc)
    next_midnight = (now_utc + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    seconds_until = (next_midnight - now_utc).total_seconds()
    return int(seconds_until)


def run_command_with_monitoring(command: str, max_transfer_bytes: int = 0, transfer_tracker: TransferTracker = None) -> tuple[int, bool]:
    """
    Run command and monitor its output with optional transfer limit.
    Returns (exit_code, was_terminated_by_limit).
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
        last_debug_time = 0  # Track last debug output time
        
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
                                
                                # Calculate daily transferred amount using tracker
                                if transfer_tracker:
                                    daily_bytes = transfer_tracker.get_daily_transferred(current_bytes)
                                    check_bytes = daily_bytes
                                else:
                                    check_bytes = current_bytes
                                
                                # Print debug info every 5 seconds
                                current_time = time.time()
                                if current_time - last_debug_time >= 5:
                                    if transfer_tracker:
                                        print(f"DEBUG: rclone total '{transferred_str}' = {current_bytes} bytes, daily = {daily_bytes} bytes, limit = {max_transfer_bytes} bytes", file=sys.stderr)
                                    else:
                                        print(f"DEBUG: Transferred '{transferred_str}' = {current_bytes} bytes, limit = {max_transfer_bytes} bytes", file=sys.stderr)
                                    last_debug_time = current_time
                                
                                if check_bytes >= max_transfer_bytes:
                                    if transfer_tracker:
                                        print(f"\nDaily transfer limit reached: {daily_bytes} bytes")
                                    else:
                                        print(f"\nMax transfer limit reached: {transferred_str}")
                                    process.terminate()
                                    return 1, True  # Terminated by limit
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
                        
                        # Check transfer limit (but don't print debug for \r updates)
                        if max_transfer_bytes > 0:
                            transferred_str = extract_transferred_amount(line)
                            if transferred_str:
                                current_bytes = parse_size_to_bytes(transferred_str)
                                
                                # Calculate daily transferred amount using tracker
                                if transfer_tracker:
                                    daily_bytes = transfer_tracker.get_daily_transferred(current_bytes)
                                    check_bytes = daily_bytes
                                else:
                                    check_bytes = current_bytes
                                
                                if check_bytes >= max_transfer_bytes:
                                    if transfer_tracker:
                                        print(f"\nDaily transfer limit reached: {daily_bytes} bytes")
                                    else:
                                        print(f"\nMax transfer limit reached: {transferred_str}")
                                    process.terminate()
                                    return 1, True  # Terminated by limit
                    else:
                        print(line)
                
                line_buffer = b''
        
        # Wait for process to complete
        return_code = process.wait()
        return return_code, False  # Natural completion
        
    except KeyboardInterrupt:
        if 'process' in locals():
            process.terminate()
        return 130, False  # User interrupted
    except Exception as e:
        print(f"Error running command: {e}", file=sys.stderr)
        return 1, False  # Error occurred


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
    
    # Initialize transfer tracker for daily limit tracking
    transfer_tracker = TransferTracker() if max_transfer_bytes > 0 else None
    
    # Run the command with monitoring in a loop until natural completion
    attempt = 1
    while True:
        print(f"\n=== Attempt {attempt} - Starting at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} ===")
        
        return_code, was_terminated_by_limit = run_command_with_monitoring(args.shell, max_transfer_bytes, transfer_tracker)
        
        if not was_terminated_by_limit:
            # Natural completion (success, error, or user interrupt)
            print(f"\nCommand completed naturally with exit code: {return_code}")
            return return_code
        
        # Was terminated by transfer limit - wait until next UTC midnight
        seconds_until_midnight = calculate_seconds_until_utc_midnight()
        next_midnight_utc = datetime.now(timezone.utc) + timedelta(seconds=seconds_until_midnight)
        
        print(f"\nTransfer limit reached. Waiting until next UTC midnight...")
        print(f"Next execution at: {next_midnight_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Sleeping for {seconds_until_midnight} seconds ({seconds_until_midnight//3600}h {(seconds_until_midnight%3600)//60}m)")
        
        try:
            # Sleep with periodic status updates every 5 seconds
            start_sleep_time = time.time()
            while True:
                current_time = time.time()
                elapsed = current_time - start_sleep_time
                remaining = seconds_until_midnight - elapsed
                
                if remaining <= 0:
                    break
                    
                print(f"Sleeping for {int(remaining)} seconds ({int(remaining)//3600}h {(int(remaining)%3600)//60}m {int(remaining)%60}s)")
                
                # Sleep for min(5 seconds, remaining time)
                sleep_duration = min(5, remaining)
                time.sleep(sleep_duration)
                
        except KeyboardInterrupt:
            print("\nInterrupted by user during sleep. Exiting...")
            return 130
            
        attempt += 1


if __name__ == '__main__':
    sys.exit(main())