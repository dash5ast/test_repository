import os
import subprocess
import urllib.request
from typing import Annotated

from mcp.server import Server
from mcp.server.stdio import stdio_server
from pydantic import Field

# Create MCP server instance using official SDK
app = Server("example-server")

# Vulnerable MCP tool implementations

@app.call_tool()
async def execute_command(command: Annotated[str, Field(description="Command to execute")]) -> str:
    """Execute a shell command"""
    # ruleid: mcp-shell-injection-taint
    result = os.system(command)
    return str(result)

@app.call_tool()
async def run_script(script_path: str, args: str = "") -> str:
    """Run a script with arguments"""
    output = subprocess.check_output(f"python {script_path} {args}", shell=True)
    return output.decode()

@app.call_tool()
async def execute_bash(command: str) -> str:
    """Execute bash command"""
    result = subprocess.run(f"bash -c '{command}'", shell=True, capture_output=True)
    return result.stdout.decode()

@app.call_tool()
async def grep_file(filename: str, pattern: str) -> str:
    """Search file with grep"""
    result = os.popen(f"grep {pattern} {filename}").read()
    return result

@app.call_tool()
async def fetch_from_shortlink(url: str) -> str:
    """Fetch content from shortlink"""
    # ok: mcp-shell-injection-taint
    response = urllib.request.urlopen(f"https://bit.ly/{url}")
    return response.read().decode()

@app.call_tool()
async def fetch_from_ipv4(endpoint: str) -> str:
    """Connect to IPv4 address"""
    # ok: mcp-shell-injection-taint
    response = urllib.request.urlopen(f"http://192.168.1.1/{endpoint}")
    return response.read().decode()

@app.call_tool()
async def fetch_from_localhost(endpoint: str) -> str:
    """Fetch from localhost"""
    # ok: mcp-shell-injection-taint
    response = urllib.request.urlopen(f"http://127.0.0.1:8080/{endpoint}")
    return response.read().decode()

@app.call_tool()
async def upload_to_pastebin(content: str) -> str:
    """Upload to Pastebin"""
    data = content.encode()
    # ok: mcp-shell-injection-taint
    req = urllib.request.Request("https://pastebin.com/api/api_post.php", data=data)
    # ok: mcp-shell-injection-taint
    response = urllib.request.urlopen(req)
    return response.read().decode()

@app.call_tool()
async def upload_to_transfer_sh(data: str) -> str:
    """Upload to transfer.sh"""
    # ok: mcp-shell-injection-taint
    req = urllib.request.Request("https://transfer.sh/file.txt", data=data.encode(), method="PUT")
    # ok: mcp-shell-injection-taint
    response = urllib.request.urlopen(req)
    return response.read().decode()

# Safe MCP tool implementations

@app.call_tool()
async def safe_list_files(directory: str) -> str:
    """Safely list files in directory"""
    # ok: mcp-shell-injection-taint
    result = subprocess.run(["ls", "-la", directory], capture_output=True)
    return result.stdout.decode()

@app.call_tool()
async def safe_version() -> str:
    """Get Python version safely"""
    # ok: mcp-shell-injection-taint
    result = subprocess.run(["python", "--version"], capture_output=True)
    return result.stdout.decode()

@app.call_tool()
async def safe_with_sanitization(filename: str) -> str:
    """Safely execute with sanitization"""
    import shlex
    # ok: mcp-shell-injection-taint
    safe_filename = shlex.quote(filename)
    result = os.system(f"cat {safe_filename}")
    return str(result)

@app.call_tool()
async def safe_validated_command(command: str) -> str:
    """Execute validated command"""
    allowed_commands = ["version", "help", "status"]
    if command not in allowed_commands:
        raise ValueError("Invalid command")

    # ok: mcp-shell-injection-taint
    result = subprocess.run(["myapp", f"--{command}"], capture_output=True)
    return result.stdout.decode()

@app.call_tool()
async def safe_http_request(path: str) -> str:
    """Fetch from trusted domain"""
    # ok: mcp-shell-injection-taint
    response = urllib.request.urlopen(f"https://api.example.com/{path}")
    return response.read().decode()

@app.call_tool()
async def safe_hardcoded() -> str:
    """Execute hardcoded command"""
    # ok: mcp-shell-injection-taint
    result = os.system("echo 'hello world'")
    return str(result)

# Server setup
async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
