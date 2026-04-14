"""
AI Vulnerability Research Loop
================================
A Mythos-style agentic vulnerability discovery framework
using Claude's API with tool use.

Author: Swarnendu Bhattacharya
GitHub: github.com/MLDreamer
Medium: medium.com/@swarnenduiitb2020

Inspired by Anthropic's Claude Mythos Preview (April 2026)
and their red team's published methodology.

IMPORTANT: Use only on code you own or have explicit permission to test.
This is for defensive security research.

Requirements:
  pip install anthropic rich

Setup:
  export ANTHROPIC_API_KEY=your_key_here
  docker pull python:3.11-slim   # for sandboxed execution
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions — the "hands" Mythos uses to interact with code
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "execute_python",
        "description": (
            "Execute Python code in a sandboxed environment. "
            "Use for writing proof-of-concept exploits, testing input handling, "
            "and confirming vulnerability conditions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute"
                },
                "description": {
                    "type": "string",
                    "description": "What this execution tests"
                }
            },
            "required": ["code", "description"]
        }
    },
    {
        "name": "execute_shell",
        "description": (
            "Execute shell commands. Use for compiling C, running binaries, "
            "examining files, or testing system interactions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                },
                "description": {
                    "type": "string",
                    "description": "What this command tests"
                }
            },
            "required": ["command", "description"]
        }
    },
    {
        "name": "read_file",
        "description": "Read a file from the analysis workspace.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "description": "Write a file to the analysis workspace (for exploit code, test harnesses, etc.)",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"}
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "report_vulnerability",
        "description": (
            "File a structured vulnerability report when you have confirmed a vulnerability. "
            "Include severity, type, root cause, PoC, and remediation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                },
                "vuln_type": {
                    "type": "string",
                    "description": "e.g. buffer overflow, use-after-free, integer overflow"
                },
                "affected_function": {"type": "string"},
                "root_cause": {"type": "string"},
                "trigger_condition": {"type": "string"},
                "poc_code": {"type": "string", "description": "Proof of concept"},
                "impact": {"type": "string"},
                "remediation": {"type": "string"}
            },
            "required": ["title", "severity", "vuln_type", "root_cause", "poc_code"]
        }
    }
]


# ─────────────────────────────────────────────────────────────────────────────
# Sandbox execution
# ─────────────────────────────────────────────────────────────────────────────

class Sandbox:
    """
    Minimal Docker-based sandbox for code execution.
    Falls back to subprocess with timeout if Docker unavailable.
    """
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.use_docker = self._check_docker()
        
    def _check_docker(self) -> bool:
        try:
            subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            console.print("[yellow]Docker not available. Using subprocess sandbox (less safe).[/yellow]")
            return False
    
    def execute_python(self, code: str) -> str:
        script_path = self.workspace / "sandbox_exec.py"
        script_path.write_text(code)
        
        if self.use_docker:
            cmd = [
                "docker", "run", "--rm",
                "--network=none",
                "--security-opt", "no-new-privileges",
                "--memory", "256m",
                "--cpus", "0.5",
                "--read-only",
                "--tmpfs", "/tmp:size=64m",
                "-v", f"{self.workspace}:/workspace:ro",
                "python:3.11-slim",
                "python", "/workspace/sandbox_exec.py"
            ]
        else:
            cmd = ["python3", str(script_path)]
        
        return self._run(cmd)
    
    def execute_shell(self, command: str) -> str:
        if self.use_docker:
            cmd = [
                "docker", "run", "--rm",
                "--network=none",
                "--security-opt", "no-new-privileges",
                "--memory", "256m",
                "-v", f"{self.workspace}:/workspace",
                "-w", "/workspace",
                "python:3.11-slim",
                "bash", "-c", command
            ]
        else:
            cmd = ["bash", "-c", f"cd {self.workspace} && {command}"]
        
        return self._run(cmd)
    
    def _run(self, cmd: list, timeout: int = 30) -> str:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]: {result.stderr}"
            return output[:4000] if output else "(no output)"
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Execution exceeded {timeout}s"
        except Exception as e:
            return f"[ERROR] {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool execution dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def execute_tool(tool_name: str, tool_input: dict, workspace: Path, sandbox: Sandbox) -> str:
    """Route tool calls to implementations."""
    
    if tool_name == "execute_python":
        code = tool_input["code"]
        desc = tool_input.get("description", "")
        console.print(f"  [cyan]→ Executing Python:[/cyan] {desc}")
        console.print(Syntax(code, "python", theme="monokai", line_numbers=False))
        result = sandbox.execute_python(code)
        console.print(f"  [dim]Result: {result[:200]}[/dim]")
        return result
    
    elif tool_name == "execute_shell":
        cmd = tool_input["command"]
        desc = tool_input.get("description", "")
        console.print(f"  [cyan]→ Shell:[/cyan] {desc} | `{cmd[:80]}`")
        result = sandbox.execute_shell(cmd)
        console.print(f"  [dim]Result: {result[:200]}[/dim]")
        return result
    
    elif tool_name == "read_file":
        path = workspace / tool_input["path"]
        try:
            return path.read_text()[:8000]
        except Exception as e:
            return f"[ERROR reading {path}]: {e}"
    
    elif tool_name == "write_file":
        path = workspace / tool_input["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(tool_input["content"])
        console.print(f"  [cyan]→ Wrote:[/cyan] {path}")
        return f"Written to {path}"
    
    elif tool_name == "report_vulnerability":
        return json.dumps({"status": "vulnerability_reported", "data": tool_input})
    
    return f"[Unknown tool: {tool_name}]"


# ─────────────────────────────────────────────────────────────────────────────
# Main agentic loop
# ─────────────────────────────────────────────────────────────────────────────

def vuln_research_loop(
    target_code: str,
    target_description: str = "the provided code",
    model: str = "claude-opus-4-6",
    max_rounds: int = 25,
    workspace_dir: Optional[str] = None
) -> list[dict]:
    """
    Run the agentic vulnerability research loop.
    
    This implements the same hypothesis → test → exploit cycle
    described in Anthropic's Mythos red team blog.
    
    Parameters
    ----------
    target_code      : Source code to analyse
    target_description: Brief description of what the code does
    model            : Claude model to use (opus recommended)
    max_rounds       : Maximum tool-use iterations
    workspace_dir    : Directory for file operations (temp dir if None)
    
    Returns
    -------
    List of vulnerability reports (each is a dict from report_vulnerability tool)
    """
    
    # Setup workspace
    if workspace_dir:
        workspace = Path(workspace_dir)
        workspace.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.mkdtemp(prefix="vuln_research_")
        workspace = Path(tmp)
    
    # Write target code to workspace
    (workspace / "target.py").write_text(target_code)
    
    sandbox = Sandbox(workspace)
    vulnerabilities = []
    
    system_prompt = """You are an expert security researcher specialising in vulnerability discovery.

Your methodology:
1. Read and understand the code semantics — what it does, what invariants it assumes
2. Identify potentially dangerous code patterns: integer arithmetic, memory operations, 
   input handling, state management, pointer arithmetic
3. Form specific hypotheses: "If input X has property Y, then condition Z occurs"
4. Test hypotheses using execute_python or execute_shell
5. For confirmed vulnerabilities: write a minimal PoC and call report_vulnerability
6. Continue until you have exhausted plausible vulnerability classes

Focus on:
- Buffer overflows / out-of-bounds writes
- Integer overflows / underflows  
- Use-after-free conditions
- Format string vulnerabilities
- Command injection
- Logic errors in bounds checking
- Off-by-one errors
- Type confusion

Be systematic. Test each hypothesis. Don't just describe — execute and confirm."""

    initial_message = f"""Analyse the following {target_description} for security vulnerabilities.

The code is available at /workspace/target.py (already written there).

Start by reading and understanding it, then systematically test your hypotheses.

```
{target_code}
```

Begin your security analysis."""

    messages = [{"role": "user", "content": initial_message}]
    
    console.print(Panel(
        f"[bold]Starting vulnerability research loop[/bold]\n"
        f"Model: {model} | Max rounds: {max_rounds}\n"
        f"Workspace: {workspace}",
        style="blue"
    ))
    
    for round_num in range(max_rounds):
        console.print(f"\n[bold]Round {round_num + 1}/{max_rounds}[/bold]")
        
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system_prompt,
            tools=TOOLS,
            messages=messages
        )
        
        # Append assistant response
        messages.append({"role": "assistant", "content": response.content})
        
        # Check stop reason
        if response.stop_reason == "end_turn":
            console.print("[green]Model completed analysis.[/green]")
            break
        
        if response.stop_reason != "tool_use":
            console.print(f"[yellow]Unexpected stop reason: {response.stop_reason}[/yellow]")
            break
        
        # Process tool calls
        tool_results = []
        for block in response.content:
            if block.type == "text" and block.text.strip():
                console.print(f"[dim]{block.text[:300]}[/dim]")
            
            elif block.type == "tool_use":
                console.print(f"\n[bold yellow]Tool:[/bold yellow] {block.name}")
                
                result = execute_tool(block.name, block.input, workspace, sandbox)
                
                # Capture vulnerability reports
                if block.name == "report_vulnerability":
                    try:
                        report_data = json.loads(result)
                        vulnerabilities.append(block.input)
                        display_vulnerability_report(block.input)
                    except json.JSONDecodeError:
                        pass
                
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result
                })
        
        # Feed results back
        messages.append({"role": "user", "content": tool_results})
    
    return vulnerabilities


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def display_vulnerability_report(report: dict):
    severity_colors = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim"
    }
    color = severity_colors.get(report.get("severity", "INFO"), "white")
    
    table = Table(title=f"[{color}]{report.get('severity', 'UNKNOWN')}[/{color}]: {report.get('title', 'Unnamed')}")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    
    for field in ["vuln_type", "affected_function", "root_cause", "trigger_condition", "impact", "remediation"]:
        value = report.get(field, "")
        if value:
            table.add_row(field.replace("_", " ").title(), str(value)[:200])
    
    console.print(table)
    
    if poc := report.get("poc_code"):
        console.print("\n[bold]Proof of Concept:[/bold]")
        console.print(Syntax(poc, "python", theme="monokai"))


# ─────────────────────────────────────────────────────────────────────────────
# Demo targets
# ─────────────────────────────────────────────────────────────────────────────

DEMO_BUFFER_OVERFLOW = '''
import ctypes
import struct

MAX_BUFFER_SIZE = 64

def process_user_data(user_input: bytes, buffer_size: int) -> bytes:
    """
    Process incoming user data into a fixed-size buffer.
    Returns processed data.
    """
    # Allocate buffer
    buffer = bytearray(MAX_BUFFER_SIZE)
    
    # Copy user data - note: no bounds check on buffer_size vs MAX_BUFFER_SIZE
    for i in range(buffer_size):
        if i < len(user_input):
            buffer[i] = user_input[i]
    
    return bytes(buffer[:buffer_size])


def parse_packet(packet: bytes) -> dict:
    """
    Parse a network packet. Format:
    [2 bytes: length][length bytes: data]
    """
    if len(packet) < 2:
        return {"error": "packet too short"}
    
    # Read length field (2 bytes, big endian)
    data_length = struct.unpack(">H", packet[:2])[0]
    
    # Extract data based on length field
    data = packet[2:2 + data_length]
    
    # Process through buffer function - passes attacker-controlled length
    processed = process_user_data(data, data_length)
    
    return {"data": processed, "length": data_length}


# Simulate receiving a malicious packet
def receive_packet(raw_bytes: bytes):
    result = parse_packet(raw_bytes)
    print(f"Parsed packet: length={result.get('length')}, data={result.get('data', b'')[:16]}...")
    return result
'''

DEMO_INTEGER_OVERFLOW = '''
import struct

def allocate_matrix(rows: int, cols: int, element_size: int = 8) -> bytearray:
    """
    Allocate a 2D matrix buffer.
    rows * cols * element_size bytes total.
    """
    # Calculate total size - potential integer overflow
    total_size = rows * cols * element_size
    
    if total_size <= 0:
        raise ValueError("Invalid matrix dimensions")
    
    if total_size > 10_000_000:
        raise ValueError("Matrix too large")
    
    return bytearray(total_size)


def read_matrix_element(buffer: bytearray, row: int, col: int, cols: int, element_size: int = 8):
    """Read element at (row, col) from buffer."""
    offset = (row * cols + col) * element_size
    
    # No bounds check on offset vs buffer size
    return buffer[offset:offset + element_size]


def process_user_matrix(rows: int, cols: int, user_row: int, user_col: int) -> bytes:
    """
    Create matrix and read user-specified element.
    rows, cols, user_row, user_col are user-controlled.
    """
    buf = allocate_matrix(rows, cols)
    element = read_matrix_element(buf, user_row, user_col, cols)
    return element
'''


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    
    console.print(Panel(
        "[bold]AI Vulnerability Research Loop[/bold]\n"
        "Inspired by Anthropic's Claude Mythos methodology\n"
        "For defensive security research only",
        style="blue"
    ))
    
    # Choose demo or provide your own code
    if len(sys.argv) > 1:
        target_file = Path(sys.argv[1])
        if not target_file.exists():
            console.print(f"[red]File not found: {target_file}[/red]")
            sys.exit(1)
        target_code = target_file.read_text()
        description = f"code from {target_file.name}"
    else:
        console.print("\nRunning demo: buffer overflow in packet parser\n")
        target_code = DEMO_BUFFER_OVERFLOW
        description = "network packet parsing code"
    
    # Run the loop
    vulns = vuln_research_loop(
        target_code=target_code,
        target_description=description,
        model="claude-opus-4-6",
        max_rounds=20
    )
    
    # Summary
    console.print("\n" + "="*60)
    console.print(f"[bold]Analysis complete. Found {len(vulns)} vulnerability(ies).[/bold]")
    
    if vulns:
        summary_table = Table(title="Vulnerability Summary")
        summary_table.add_column("Severity")
        summary_table.add_column("Title")
        summary_table.add_column("Type")
        
        for v in vulns:
            summary_table.add_row(
                v.get("severity", "?"),
                v.get("title", "Untitled"),
                v.get("vuln_type", "?")
            )
        
        console.print(summary_table)
