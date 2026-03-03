#!/usr/bin/env python3
"""
ScriptSnoop v2.0 - Script Security Scanner
Scans scripts for risky patterns with severity levels, CLI args, and export support.
Author: logesh-GIT001 | No external dependencies required.
"""

import os
import re
import glob
import json
import csv
import argparse
import sys
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# RISKY PATTERNS with severity and description
# ─────────────────────────────────────────────
# Severity: CRITICAL > HIGH > MEDIUM > LOW
RISKY_PATTERNS = [
    # ── CRITICAL ──────────────────────────────────────────────
    {
        "id": "RP001",
        "pattern": r'rm\s+-[rRfF]{2,}',
        "severity": "CRITICAL",
        "description": "Recursive force delete (rm -rf) — can wipe entire directories",
        "category": "Destructive",
    },
    {
        "id": "RP002",
        "pattern": r'dd\s+if=/dev/(zero|null|random)',
        "severity": "CRITICAL",
        "description": "dd with /dev/zero or /dev/random — disk wipe or overwrite",
        "category": "Destructive",
    },
    {
        "id": "RP003",
        "pattern": r'mkfs\b',
        "severity": "CRITICAL",
        "description": "mkfs — formats/wipes a filesystem",
        "category": "Destructive",
    },
    {
        "id": "RP004",
        "pattern": r'(curl|wget)\s+.{0,200}\|\s*(bash|sh|zsh|python)',
        "severity": "CRITICAL",
        "description": "Remote code execution via pipe to shell — classic malware vector",
        "category": "Remote Execution",
    },
    {
        "id": "RP005",
        "pattern": r'\beval\s*\(',
        "severity": "CRITICAL",
        "description": "eval() — executes arbitrary code strings; high injection risk",
        "category": "Code Injection",
    },
    {
        "id": "RP006",
        "pattern": r'__import__\s*\(',
        "severity": "CRITICAL",
        "description": "Dynamic __import__() — can load arbitrary modules at runtime",
        "category": "Code Injection",
    },
    {
        "id": "RP007",
        "pattern": r'pickle\.(loads?|Unpickler)',
        "severity": "CRITICAL",
        "description": "pickle.load/loads — deserializes arbitrary Python objects; RCE risk",
        "category": "Unsafe Deserialization",
    },
    {
        "id": "RP008",
        "pattern": r'marshal\.loads?\s*\(',
        "severity": "CRITICAL",
        "description": "marshal.load/loads — can execute arbitrary bytecode",
        "category": "Unsafe Deserialization",
    },

    # ── HIGH ──────────────────────────────────────────────────
    {
        "id": "RP009",
        "pattern": r'sudo\s+.*(rm|dd|mkfs|chmod|chown|passwd|usermod)',
        "severity": "HIGH",
        "description": "sudo with destructive/privilege commands",
        "category": "Privilege Escalation",
    },
    {
        "id": "RP010",
        "pattern": r'chmod\s+(777|a\+rwx|o\+w)',
        "severity": "HIGH",
        "description": "World-writable permissions (chmod 777) — severe security misconfiguration",
        "category": "Permissions",
    },
    {
        "id": "RP011",
        "pattern": r'subprocess\.(call|Popen|run)\s*\(\s*[\[\(]?\s*["\']?\s*(sudo|rm\s+-|chmod\s+777|curl|wget|dd\s)',
        "severity": "HIGH",
        "description": "subprocess with dangerous system commands",
        "category": "Command Execution",
    },
    {
        "id": "RP012",
        "pattern": r'os\.system\s*\(',
        "severity": "HIGH",
        "description": "os.system() — executes shell commands; prefer subprocess with args list",
        "category": "Command Execution",
    },
    {
        "id": "RP013",
        "pattern": r'(exec|execv|execve|execvp)\s*\(',
        "severity": "HIGH",
        "description": "exec/execv variants — replaces current process with another",
        "category": "Command Execution",
    },
    {
        "id": "RP014",
        "pattern": r'base64\.(b64decode|decodebytes)\s*\(',
        "severity": "HIGH",
        "description": "base64 decode — often used to hide obfuscated payloads",
        "category": "Obfuscation",
    },
    {
        "id": "RP015",
        "pattern": r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}',
        "severity": "HIGH",
        "description": "Long hex-encoded string — possible obfuscated payload",
        "category": "Obfuscation",
    },

    # ── MEDIUM ────────────────────────────────────────────────
    {
        "id": "RP016",
        "pattern": r'os\.(remove|unlink|rmdir|removedirs)\s*\(',
        "severity": "MEDIUM",
        "description": "Python file/directory deletion functions",
        "category": "Destructive",
    },
    {
        "id": "RP017",
        "pattern": r'shutil\.(rmtree|move)\s*\(',
        "severity": "MEDIUM",
        "description": "shutil.rmtree/move — recursive directory removal or overwrite",
        "category": "Destructive",
    },
    {
        "id": "RP018",
        "pattern": r'subprocess\.(call|Popen|run)\s*\(.{0,80}shell\s*=\s*True',
        "severity": "MEDIUM",
        "description": "subprocess with shell=True — enables shell injection attacks",
        "category": "Command Execution",
    },
    {
        "id": "RP019",
        "pattern": r'(urllib\.request\.urlopen|httpx?\.(get|post|put|delete))\s*\(',
        "severity": "MEDIUM",
        "description": "HTTP request — verify URLs are not user-controlled (SSRF risk)",
        "category": "Network",
    },
    {
        "id": "RP020",
        "pattern": r'socket\.(connect|bind|listen)\s*\(',
        "severity": "MEDIUM",
        "description": "Raw socket usage — potential backdoor or port scanning",
        "category": "Network",
    },
    {
        "id": "RP021",
        "pattern": r'(password|passwd|secret|api_key|token|private_key)\s*=\s*["\'][^"\']{4,}["\']',
        "severity": "MEDIUM",
        "description": "Hardcoded credential or secret detected",
        "category": "Secrets",
    },
    {
        "id": "RP022",
        "pattern": r'\b([0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "severity": "MEDIUM",
        "description": "Hardcoded IP address — review if this is intentional",
        "category": "Network",
    },

    # ── LOW ───────────────────────────────────────────────────
    {
        "id": "RP023",
        "pattern": r'requests\.(get|post|put|delete|patch|head)\s*\(',
        "severity": "LOW",
        "description": "requests HTTP call — ensure URLs are not user-controlled",
        "category": "Network",
    },
    {
        "id": "RP024",
        "pattern": r'(print|logging\.(debug|info|warning|error))\s*\(.{0,80}(password|token|secret|key)',
        "severity": "LOW",
        "description": "Possible secret/credential being logged or printed",
        "category": "Secrets",
    },
    {
        "id": "RP025",
        "pattern": r'chmod\s+(755|644|a\+x)',
        "severity": "LOW",
        "description": "chmod with broad permissions — verify if this is intentional",
        "category": "Permissions",
    },
    {
        "id": "RP026",
        "pattern": r'import\s+(pty|telnetlib)\b',
        "severity": "LOW",
        "description": "PTY/Telnet module import — common in reverse shells",
        "category": "Network",
    },
    {
        "id": "RP027",
        "pattern": r'(#\s*TODO|#\s*FIXME|#\s*HACK|#\s*XXX)',
        "severity": "LOW",
        "description": "Unresolved TODO/FIXME/HACK comment — may indicate incomplete security logic",
        "category": "Code Quality",
    },
]

# ─────────────────────────────────────────────
# Severity ordering for sorting/filtering
# ─────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLORS = {
    "CRITICAL": "\033[1;31m",  # Bold Red
    "HIGH":     "\033[0;31m",  # Red
    "MEDIUM":   "\033[0;33m",  # Yellow
    "LOW":      "\033[0;36m",  # Cyan
    "RESET":    "\033[0m",
    "GREEN":    "\033[0;32m",
    "BOLD":     "\033[1m",
}

SUPPORTED_EXTENSIONS = ['*.py', '*.sh', '*.bat', '*.ps1', '*.rb', '*.php', '*.js']


# ─────────────────────────────────────────────
# Core scanning logic
# ─────────────────────────────────────────────

def find_files(directory, extensions):
    """Recursively find files with given extensions."""
    found = []
    for ext in extensions:
        pattern = os.path.join(directory, '**', ext)
        found.extend(glob.glob(pattern, recursive=True))
    # Deduplicate (some globs may overlap)
    return list(set(found))


def is_comment_line(line, file_ext):
    """Check if a stripped line is purely a comment."""
    comment_markers = {
        '.py':  r'^\s*#',
        '.sh':  r'^\s*#',
        '.bat': r'^\s*(rem\b|::)',
        '.ps1': r'^\s*#',
        '.rb':  r'^\s*#',
        '.php': r'^\s*(//|#|/\*)',
        '.js':  r'^\s*(//|/\*)',
    }
    marker = comment_markers.get(file_ext, r'^\s*#')
    return bool(re.match(marker, line, re.IGNORECASE))


def strip_inline_comment(line, file_ext):
    """Remove trailing inline comment from a line."""
    if file_ext in ('.py', '.sh', '.rb', '.ps1'):
        # Only strip # outside of strings (simple heuristic)
        result = re.sub(r'\s+#[^"\']*$', '', line)
        return result
    return line


def scan_file(file_path, patterns, script_path, min_severity=None):
    """
    Scan a single file for risky patterns.
    Returns list of finding dicts.
    """
    findings = []

    # Never scan ourselves
    if os.path.abspath(file_path) == script_path:
        return findings

    file_ext = Path(file_path).suffix.lower()
    seen_lines = set()  # Deduplicate: (line_num, pattern_id)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"  [!] Error reading {file_path}: {e}")
        return findings

    for line_num, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()

        if not stripped:
            continue

        # Skip pure comment lines
        if is_comment_line(stripped, file_ext):
            continue

        # Remove inline comments for cleaner matching
        clean_line = strip_inline_comment(stripped, file_ext)

        for rule in patterns:
            # Apply severity filter
            if min_severity and SEVERITY_ORDER.get(rule["severity"], 99) > SEVERITY_ORDER.get(min_severity, 99):
                continue

            dedup_key = (line_num, rule["id"])
            if dedup_key in seen_lines:
                continue

            if re.search(rule["pattern"], clean_line, re.IGNORECASE):
                seen_lines.add(dedup_key)
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "pattern": rule["pattern"],
                    "content": stripped[:120] + ("..." if len(stripped) > 120 else ""),
                })

    return findings


# ─────────────────────────────────────────────
# Output functions
# ─────────────────────────────────────────────

def color(text, severity_or_key):
    """Wrap text in ANSI color codes."""
    code = SEVERITY_COLORS.get(severity_or_key, "")
    reset = SEVERITY_COLORS["RESET"]
    return f"{code}{text}{reset}"


def print_findings(all_findings, no_color=False):
    """Print findings to terminal, grouped by severity."""
    if not all_findings:
        msg = "✅  No risky patterns found. All scanned files appear clean."
        print(color(msg, "GREEN") if not no_color else msg)
        return

    sorted_findings = sorted(all_findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["file"], f["line"]))

    current_severity = None
    for f in sorted_findings:
        if f["severity"] != current_severity:
            current_severity = f["severity"]
            header = f"\n{'═'*60}\n  {current_severity} FINDINGS\n{'═'*60}"
            print(color(header, current_severity) if not no_color else header)

        sev_tag = f"[{f['severity']:<8}]"
        line = (
            f"  {color(sev_tag, f['severity']) if not no_color else sev_tag} "
            f"{f['rule_id']} | {f['file']}:{f['line']}\n"
            f"  {'─'*4} {f['description']}\n"
            f"  {'─'*4} Code: {f['content']}\n"
        )
        print(line)


def print_summary(all_findings, total_files, scanned_files, elapsed):
    """Print a summary table."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    affected_files = set()
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        affected_files.add(f["file"])

    print(f"\n{'═'*60}")
    print(color(f"  SCAN SUMMARY", "BOLD"))
    print(f"{'═'*60}")
    print(f"  Scan time      : {elapsed:.2f}s")
    print(f"  Files found    : {total_files}")
    print(f"  Files scanned  : {scanned_files}")
    print(f"  Files with issues: {len(affected_files)}")
    print(f"  Total findings : {len(all_findings)}")
    print(f"  ─── Breakdown ───────────────────────")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        bar = "█" * counts[sev] if counts[sev] else "·"
        print(f"  {color(f'{sev:<10}', sev)} : {counts[sev]:>4}  {bar}")
    print(f"{'═'*60}\n")

    if counts["CRITICAL"] > 0:
        print(color("  ⚠️  CRITICAL issues found — immediate review recommended!", "CRITICAL"))
    elif counts["HIGH"] > 0:
        print(color("  ⚠️  HIGH severity issues found — review before deployment.", "HIGH"))
    else:
        print(color("  ✅  No critical or high severity issues found.", "GREEN"))


def export_json(all_findings, output_path, scan_meta):
    """Export findings to JSON."""
    data = {
        "meta": scan_meta,
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"  📄 JSON report saved: {output_path}")


def export_csv(all_findings, output_path):
    """Export findings to CSV."""
    fieldnames = ["rule_id", "severity", "category", "file", "line", "description", "content"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasdict="ignore")
        writer.writeheader()
        for finding in all_findings:
            writer.writerow({k: finding.get(k, "") for k in fieldnames})
    print(f"  📊 CSV report saved: {output_path}")


def export_html(all_findings, output_path, scan_meta):
    """Export findings as a standalone HTML report."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    sev_colors_html = {
        "CRITICAL": "#e53e3e",
        "HIGH": "#dd6b20",
        "MEDIUM": "#d69e2e",
        "LOW": "#3182ce",
    }

    rows = ""
    for f in sorted(all_findings, key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["file"], x["line"])):
        color_hex = sev_colors_html.get(f["severity"], "#999")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color_hex}">{f['severity']}</span></td>
          <td>{f['rule_id']}</td>
          <td>{f['category']}</td>
          <td style="font-family:monospace;font-size:12px">{f['file']}:{f['line']}</td>
          <td>{f['description']}</td>
          <td style="font-family:monospace;font-size:12px;color:#555">{f['content']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ScriptSnoop Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f7fafc; color: #2d3748; }}
  header {{ background: #1a202c; color: white; padding: 24px 40px; }}
  header h1 {{ margin: 0; font-size: 24px; }} header p {{ margin: 4px 0 0; color: #a0aec0; font-size: 13px; }}
  .stats {{ display: flex; gap: 16px; padding: 24px 40px; flex-wrap: wrap; }}
  .stat {{ background: white; border-radius: 8px; padding: 16px 24px; min-width: 120px; box-shadow: 0 1px 3px rgba(0,0,0,.1); text-align:center; }}
  .stat .num {{ font-size: 32px; font-weight: 700; }}
  .stat .lbl {{ font-size: 12px; color: #718096; margin-top: 4px; }}
  .container {{ padding: 0 40px 40px; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); font-size:13px; }}
  th {{ background: #2d3748; color: white; padding: 10px 14px; text-align: left; font-weight: 600; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f7fafc; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 700; }}
  footer {{ text-align: center; padding: 20px; color: #a0aec0; font-size: 12px; }}
</style>
</head>
<body>
<header>
  <h1>🔍 ScriptSnoop Security Report</h1>
  <p>Scanned: {scan_meta['target_directory']} &nbsp;|&nbsp; {scan_meta['scan_time']} &nbsp;|&nbsp; {scan_meta['files_scanned']} files scanned</p>
</header>
<div class="stats">
  <div class="stat"><div class="num" style="color:#e53e3e">{counts['CRITICAL']}</div><div class="lbl">CRITICAL</div></div>
  <div class="stat"><div class="num" style="color:#dd6b20">{counts['HIGH']}</div><div class="lbl">HIGH</div></div>
  <div class="stat"><div class="num" style="color:#d69e2e">{counts['MEDIUM']}</div><div class="lbl">MEDIUM</div></div>
  <div class="stat"><div class="num" style="color:#3182ce">{counts['LOW']}</div><div class="lbl">LOW</div></div>
  <div class="stat"><div class="num">{len(all_findings)}</div><div class="lbl">Total Findings</div></div>
</div>
<div class="container">
  {"<p style='color:#38a169;font-weight:600'>✅ No risky patterns found.</p>" if not all_findings else ""}
  {"<table><thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Description</th><th>Code Snippet</th></tr></thead><tbody>" + rows + "</tbody></table>" if all_findings else ""}
</div>
<footer>Generated by ScriptSnoop v2.0</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  🌐 HTML report saved: {output_path}")


# ─────────────────────────────────────────────
# Argument parsing & main
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="scriptsnoop",
        description="ScriptSnoop v2.0 — Script Security Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python scriptsnoop.py                         # Interactive mode
  python scriptsnoop.py --path ./myproject      # Scan a directory
  python scriptsnoop.py --path . --min-severity HIGH
  python scriptsnoop.py --path . --output report.json --format json
  python scriptsnoop.py --path . --output report.html --format html
  python scriptsnoop.py --path . --no-color --quiet
"""
    )
    parser.add_argument("--path", "-p", default=None,
        help="Directory to scan (default: prompt interactively)")
    parser.add_argument("--ext", "-e", nargs="+",
        default=SUPPORTED_EXTENSIONS,
        metavar="EXT",
        help=f"File extensions to scan (default: {' '.join(SUPPORTED_EXTENSIONS)})")
    parser.add_argument("--min-severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Only report findings at or above this severity")
    parser.add_argument("--output", "-o", default=None,
        help="Output file path for report (e.g. report.json, report.html, report.csv)")
    parser.add_argument("--format", "-f",
        choices=["json", "csv", "html"],
        default=None,
        help="Export format (inferred from --output extension if not set)")
    parser.add_argument("--no-color", action="store_true",
        help="Disable colored terminal output")
    parser.add_argument("--quiet", "-q", action="store_true",
        help="Only print summary, suppress per-finding details")
    parser.add_argument("--list-rules", action="store_true",
        help="List all detection rules and exit")
    return parser.parse_args()


def list_rules():
    """Print all rules in a table."""
    print(f"\n{'═'*80}")
    print(f"  {'ID':<8} {'SEV':<10} {'CATEGORY':<22} DESCRIPTION")
    print(f"{'═'*80}")
    for rule in RISKY_PATTERNS:
        sev = rule['severity']
        sev_padded = f"{sev:<10}"
        print(f"  {rule['id']:<8} {color(sev_padded, sev)} {rule['category']:<22} {rule['description']}")
    print(f"{'═'*80}\n")


def infer_format(output_path):
    """Infer export format from file extension."""
    if not output_path:
        return None
    ext = Path(output_path).suffix.lower()
    return {"json": "json", ".json": "json", ".csv": "csv", ".html": "html"}.get(ext)


def main():
    import time
    args = parse_args()

    if args.list_rules:
        list_rules()
        sys.exit(0)

    # ── Resolve target directory ─────────────────────────────
    if args.path:
        target_dir = os.path.expanduser(os.path.normpath(args.path))
    else:
        raw = input("Enter folder path to scan (or press Enter for current folder): ").strip()
        target_dir = os.path.expanduser(os.path.normpath(raw)) if raw else "."

    if not os.path.isdir(target_dir):
        print(f"❌ Error: '{target_dir}' is not a valid directory.")
        sys.exit(1)

    abs_dir = os.path.abspath(target_dir)
    script_path = os.path.abspath(__file__)

    # ── Resolve export format ────────────────────────────────
    export_format = args.format or infer_format(args.output)

    # ── Print header ─────────────────────────────────────────
    if not args.quiet:
        print(color(f"\n🔍 ScriptSnoop v2.0 — Script Security Scanner", "BOLD"))
        print(f"   Target     : {abs_dir}")
        print(f"   Extensions : {' '.join(args.ext)}")
        if args.min_severity:
            print(f"   Min severity: {args.min_severity}")
        print()

    # ── Find & scan files ────────────────────────────────────
    start = time.time()
    files = find_files(abs_dir, args.ext)

    if not files:
        print(f"❌ No supported files found in '{abs_dir}'.")
        sys.exit(0)

    print(f"  Found {len(files)} file(s) to scan...")

    all_findings = []
    for fp in sorted(files):
        findings = scan_file(fp, RISKY_PATTERNS, script_path, min_severity=args.min_severity)
        all_findings.extend(findings)

    elapsed = time.time() - start

    # ── Output results ───────────────────────────────────────
    if not args.quiet:
        print_findings(all_findings, no_color=args.no_color)

    print_summary(all_findings, len(files), len(files), elapsed)

    # ── Export report ────────────────────────────────────────
    if args.output and export_format:
        scan_meta = {
            "tool": "ScriptSnoop v2.0",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_directory": abs_dir,
            "files_scanned": len(files),
            "min_severity": args.min_severity or "ALL",
        }
        if export_format == "json":
            export_json(all_findings, args.output, scan_meta)
        elif export_format == "csv":
            export_csv(all_findings, args.output)
        elif export_format == "html":
            export_html(all_findings, args.output, scan_meta)
    elif args.output:
        print(f"  ⚠️  Could not infer format from '{args.output}'. Use --format json/csv/html.")

    print()
    # Exit code: 0 = clean, 1 = issues found (useful for CI/CD)
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
