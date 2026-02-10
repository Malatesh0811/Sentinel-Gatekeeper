import ast
import networkx as nx
import sys
import os

# Ensure we can import from the app folder
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

# Import your actual engine logic
from app.main import VulnerabilityVisitor

# --- TEST DATA 1: SAFE INTERNAL CODE ---
# Logic: Uses os.system (dangerous), BUT is on an internal route.
# Expected: ALLOW
SAFE_CODE = """
import os
from fastapi import FastAPI
app = FastAPI()

@app.post("/internal/backup")
def run_backup():
    os.system("backup_db.sh")
"""

# --- TEST DATA 2: UNSAFE PUBLIC CODE ---
# Logic: Uses subprocess (dangerous) AND is on a public route.
# Expected: BLOCK
UNSAFE_CODE = """
import subprocess
from fastapi import FastAPI
app = FastAPI()

@app.get("/public/hack")
def hack_me(cmd: str):
    subprocess.call(cmd, shell=True)
"""

def test_logic():
    print("--- RUNNING SECURITY TESTS ---")
    
    # TEST 1: SAFE CODE
    print("\n[TEST 1] Checking Internal Tool (Should be ALLOWED)...")
    visitor = VulnerabilityVisitor()
    tree = ast.parse(SAFE_CODE)
    
    # Simulate the Environment (The API usually does this part)
    visitor.graph.add_node("INTERNET", type='source')
    visitor.visit(tree)
    
    # Check Reachability
    blocked = False
    for vuln in visitor.vulnerabilities:
        if nx.has_path(visitor.graph, "INTERNET", vuln):
            blocked = True
            
    if not blocked:
        print("✅ PASS: Internal tool was correctly ALLOWED.")
    else:
        print("❌ FAIL: Internal tool was incorrectly BLOCKED.")
        exit(1) # Fail the pipeline

    # TEST 2: UNSAFE CODE
    print("\n[TEST 2] Checking Public Exploit (Should be BLOCKED)...")
    visitor = VulnerabilityVisitor()
    tree = ast.parse(UNSAFE_CODE)
    
    # Simulate the Environment
    visitor.graph.add_node("INTERNET", type='source')
    visitor.visit(tree)
    
    # Check Reachability
    blocked = False
    for vuln in visitor.vulnerabilities:
        if nx.has_path(visitor.graph, "INTERNET", vuln):
            blocked = True
            
    if blocked:
        print("✅ PASS: Public exploit was correctly BLOCKED.")
    else:
        print("❌ FAIL: Public exploit was incorrectly ALLOWED.")
        exit(1) # Fail the pipeline

if __name__ == "__main__":
    test_logic()
