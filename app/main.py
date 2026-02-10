import ast
import json
import os
import shutil
import datetime
import subprocess
import networkx as nx
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()

# --- CONFIGURATION ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# --- DATA MODELS ---
class CodePayload(BaseModel):
    code: str
    requirements: str

# --- AST ANALYSIS ENGINE ---
class VulnerabilityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.graph = nx.DiGraph()
        self.current_function = None
        self.vulnerabilities = []
        
        # DEFINING THE "DANGEROUS" FUNCTIONS
        # This list tells the engine what to look for.
        self.dangerous_sinks = [
            'yaml.load', 
            'subprocess.call', 'subprocess.run', 'subprocess.Popen',
            'os.system', 'os.popen',
            'eval', 'exec', 'pickle.loads'
        ]

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.graph.add_node(node.name, type='function', color='#2d3442', label=node.name)
        
        # Detect Routes (FastAPI/Flask decorators)
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and hasattr(decorator.func, 'attr'):
                # Check for @app.get, @app.post, etc.
                if decorator.func.attr in ['get', 'post', 'put', 'delete']:
                    # Get the route path (e.g., "/public/network_tool")
                    if decorator.args:
                        route_path = decorator.args[0].value
                        
                        # Add Route Node
                        route_id = f"ROUTE: {route_path}"
                        self.graph.add_node(route_id, type='route', color='#ff9f1c', label=route_path)
                        self.graph.add_edge(route_id, node.name)

                        # Check Reachability (Public vs Internal)
                        # If the route does NOT start with /internal or /admin, it is PUBLIC.
                        if not (route_path.startswith("/internal") or route_path.startswith("/admin")):
                            self.graph.add_edge("INTERNET", route_id)
        
        self.generic_visit(node)
        self.current_function = None

    def visit_Call(self, node):
        # Identify the function being called
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handles module.function (e.g., subprocess.call)
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"

        # CHECK IF DANGEROUS
        if func_name and func_name in self.dangerous_sinks:
            vuln_id = f"VULN: {func_name}"
            self.vulnerabilities.append(vuln_id)
            
            # Add Vulnerability Node (Red)
            self.graph.add_node(vuln_id, type='vulnerability', color='#ff3355', label=f"⚠️ {func_name}")
            
            # Connect current function to this vulnerability
            if self.current_function:
                self.graph.add_edge(self.current_function, vuln_id)

        self.generic_visit(node)

# --- ANALYSIS ENDPOINT ---
@app.post("/api/analyze")
async def analyze_code(payload: CodePayload):
    logs = ["START: Received analysis request."]
    visitor = VulnerabilityVisitor()
    
    # 1. Parse Code
    try:
        tree = ast.parse(payload.code)
    except SyntaxError as e:
        return {"decision": "ERROR", "logs": [f"Syntax Error: {str(e)}"], "graph": []}

    # 2. Add Internet Node
    visitor.graph.add_node("INTERNET", type='source', color='#00f2ff', label='INTERNET')

    # 3. Walk the AST
    logs.append("INFO: Building Abstract Syntax Tree (AST)...")
    visitor.visit(tree)

    # 4. Check Reachability (The "Context" Logic)
    decision = "ALLOW"
    logs.append("INFO: Constructing Context Graph...")
    
    # We assume 'ALLOW' unless we find a specific kill chain
    vulnerability_found = False

    if not visitor.vulnerabilities:
        logs.append("SUCCESS: No dangerous sinks (e.g. subprocess, yaml.load) found in code.")
    
    for vuln in visitor.vulnerabilities:
        vulnerability_found = True
        try:
            # Check if there is a path from INTERNET to the VULNERABILITY
            if nx.has_path(visitor.graph, "INTERNET", vuln):
                decision = "BLOCK"
                path = nx.shortest_path(visitor.graph, "INTERNET", vuln)
                path_str = " -> ".join(path)
                logs.append(f"CRITICAL: Kill Chain Detected! {path_str}")
                logs.append(f"ALERT: Blocking deployment due to reachable '{vuln}'")
                break # Block on first critical find
            else:
                logs.append(f"WARNING: Found '{vuln}', but it is internal/safe (No path from INTERNET).")
        except Exception as e:
            logs.append(f"ERROR: Graph traversal failed: {e}")

    # 5. Run External Scanners (Trivy/Semgrep) - Optional but good for logs
    # We keep this lightweight for the demo to focus on the Graph Engine
    if decision == "ALLOW" and vulnerability_found:
        logs.append("INFO: Vulnerabilities found but marked SAFE due to lack of public reachability.")
    elif decision == "ALLOW":
        logs.append("INFO: Code looks clean.")

    # 6. Format Graph for Frontend (Cytoscape)
    cytoscape_elements = []
    for node, attrs in visitor.graph.nodes(data=True):
        cytoscape_elements.append({"data": {"id": node, **attrs}})
    for source, target in visitor.graph.edges():
        cytoscape_elements.append({"data": {"source": source, "target": target}})

    return {
        "decision": decision,
        "logs": logs,
        "graph": cytoscape_elements
    }

# --- SERVE UI ---
@app.get("/")
def read_root():
    return FileResponse('app/static/index.html')

@app.get("/demo")
def read_demo():
    return FileResponse('app/static/demo.html')

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
