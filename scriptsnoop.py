#!/usr/bin/env python3
import os
import glob
import re
from pathlib import Path

# Define risky patterns (regex for flexibility; case-insensitive)
# These now catch both direct commands and quoted ones in Python/shell executions
RISKY_PATTERNS = [
    r'rm\s+-rf',  # rm -rf (destructive delete)
    r'curl\s+.*\|.*(bash|sh)',  # curl piped to shell (common malware vector)
    r'wget\s+.*\|.*(bash|sh)',  # wget piped to shell
    r'sudo\s+.*(rm|dd|mkfs|chmod)',  # sudo with destructive commands (now includes chmod)
    r'chmod\s+777',  # chmod 777 (overly permissive)
    r'dd\s+if=/dev/zero',  # dd to wipe data
    r'os\.(remove|unlink|rmdir)',  # Python file deletions (os.remove, etc.)
    r'(requests\.get|urllib\.request\.urlopen)\s*\(',  # Python network calls (requests.get, urllib)
    r'subprocess\.(call|Popen|run)\s*\(\s*["\']?\s*(sudo|rm|chmod|curl)',  # Python subprocess with risky commands
    # Add more as needed, e.g., r'eval\s*\(' for code injection
]

def find_risky_files(directory, extensions=['*.py', '*.sh', '*.bat']):
    """
    Recursively find files with given extensions in the directory.
    """
    risky_files = []
    for ext in extensions:
        pattern = os.path.join(directory, '**', ext)
        risky_files.extend(glob.glob(pattern, recursive=True))
    return risky_files

def scan_file(file_path, patterns):
    """
    Scan a single file for risky patterns.
    Scans both full lines (for quoted risks) and de-quoted lines (for code).
    Skips pure comments.
    """
    matches = []
    script_itself = os.path.abspath(__file__)  # Path to this script
    if os.path.abspath(file_path) == script_itself:
        return matches  # Skip scanning ourselves to avoid false positives

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                original_line = line.strip()
                # Skip if the entire line is a comment (starts with #, //, or /*)
                if re.match(r'^\s*(#|//|/\*)', original_line):
                    continue

                # Scan the full original line (catches quoted strings like "rm -rf")
                for pattern in patterns:
                    if re.search(pattern, original_line, re.IGNORECASE):
                        matches.append({
                            'file': file_path,
                            'line': line_num,
                            'pattern': pattern,
                            'content': original_line[:100] + '...' if len(original_line) > 100 else original_line
                        })
                        break  # Avoid duplicate matches on same line

                # Also scan de-quoted version (for non-quoted code, reduces some FPs)
                # Remove single/double quotes and backticks
                line_no_quotes = re.sub(r'"[^"]*"|\'[^\']*\'|`[^`]*`', '', original_line)
                for pattern in patterns:
                    if re.search(pattern, line_no_quotes, re.IGNORECASE):
                        matches.append({
                            'file': file_path,
                            'line': line_num,
                            'pattern': pattern + ' (de-quoted)',
                            'content': original_line[:100] + '...' if len(original_line) > 100 else original_line
                        })
                        break

    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

def main():
    """
    Main function: Prompt for directory and scan for findings.
    """
    # Ask user to input the folder path to scan
    target_dir = input("Please enter the folder path you want to scan (or press Enter for current folder): ").strip()
    if not target_dir:
        target_dir = '.'  # default to current directory if empty input

    # Normalize path (handles spaces, etc.)
    target_dir = os.path.expanduser(os.path.normpath(target_dir))

    # Ensure the directory exists
    if not os.path.exists(target_dir):
        print(f"❌ Error: The directory '{target_dir}' does not exist. Please check the path and try again.")
        return

    print(f"Scanning directory: {os.path.abspath(target_dir)}")
    files = find_risky_files(target_dir)
    
    if not files:
        print("❌ No supported files (.py, .sh, .bat) found in the directory or subdirectories.")
        return
    
    print(f"Found {len(files)} files to scan.")
    
    all_matches = []
    for file_path in files:
        matches = scan_file(file_path, RISKY_PATTERNS)
        all_matches.extend(matches)
    
    if all_matches:
        print(f"\n🚨 Found {len(all_matches)} risky patterns in {len(files)} files:")
        for match in all_matches:
            print(f"  File: {match['file']} | Line {match['line']} | Pattern: {match['pattern']} | Content: {match['content']}")
        print("\n⚠️  Review these manually—some may be false positives or legitimate in context.")
    else:
        print("✅ No risky patterns found. All files appear safe based on current rules.")

if __name__ == "__main__":
    main()
