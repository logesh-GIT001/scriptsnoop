# ScriptSnoop: Script Security Scanner

**ScriptSnoop** is a simple Python tool that scans `.py`, `.sh`, and `.bat` files for risky commands like `rm -rf`, `sudo`, `chmod 777`, and suspicious network calls. It's for cybersecurity checks, auditing scripts, or learning secure coding.

Built with standard Python—no extra installs needed. Detects patterns in code, even quoted ones (e.g., `os.system("rm -rf")`).

## Features

- Interactive: Prompts for folder to scan (or use current folder).
- Recursive: Scans subfolders.
- Reduces false positives: Ignores comments and skips self-scans.
- Cross-platform: Works on Windows, Linux, macOS.
- Easy to extend: Add patterns in the code.

## Supported Risks

- Destructive deletes: `rm -rf`, `os.remove`.
- Remote execution: `curl | bash`, `requests.get`.
- Permissions: `sudo` with `rm/chmod`, `chmod 777`.
- Data wipe: `dd if=/dev/zero`.
- More: Python `subprocess` with risky args.

## Installation

1. Ensure Python 3.6+ is installed ([python.org](https://www.python.org/downloads/)).
2. Save the code as `scriptsnoop.py` in a folder.
3. (Optional) Create test files for practice.

## Usage

Run in terminal/PowerShell:

```bash
python scriptsnoop.py

```
## Author

- Developed by Logeswaran (https://www.linkedin.com/in/logeshwaran-s-b5aa5b27b).
- Cybersecurity enthusiast building simple security tools and scripts for automation.



