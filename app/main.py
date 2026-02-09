import subprocess
import ast
import json
import os
import shutil
import datetime
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from fastapi.responses import FileResponse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

class CodeInput(BaseModel):
    code: str
    requirements: str

# Logger Helper
def log(msg, buffer):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    buffer.append(f"[{timestamp}] {msg}")

def run_security_scan(log_buffer):
    results = []
    log("INFO: Initializing Trivy (Dependency Scanner)...", log_buffer)
    
    if os.path.exists("requirements.txt") and os.path.getsize("requirements.txt") > 0:
        if shutil.which("trivy"):
            subprocess.run("trivy fs . --format json --output trivy_results.json --scanners config,vuln,secret", shell=True)
            try:
                with open("trivy_results.json") as f:
                    data = json.load(f)
                    if "Results" in data:
                        for res in data["Results"]:
                            for v in res.get("Vulnerabilities", []):
                                results.append({
                                    "source": "Trivy",
                                    "id": v["VulnerabilityID"],
                                    "severity": v["Severity"],
                                    "pkg_name": v["PkgName"],
                                    "description": v.get("Description", "")
                                })
                log(f"SUCCESS: Trivy found potential vulnerabilities.", log_buffer)
            except Exception as e:
                log(f"ERROR: Trivy failed to parse results: {e}", log_buffer)
        else:
            log("WARN: Trivy not installed.", log_buffer)

    log("INFO: Initializing Semgrep (SAST Scanner)...", log_buffer)
    if shutil.which("semgrep"):
        subprocess.run("semgrep scan --config=auto --json --output=semgrep_results.json temp_main.py", shell=True)
        try:
            with open("semgrep_results.json") as f:
                data = json.load(f)
                count = 0
                for res in data.get("results", []):
                    results.append({
                        "source": "Semgrep",
                        "id": res["check_id"],
                        "severity": res["extra"]["severity"],
                        "file": "main.py",
                        "line": res["start"]["line"],
                        "code_snippet": res["extra"]["lines"]
                    })
                    count += 1
                log(f"SUCCESS: Semgrep analysis complete. {count} issues found.", log_buffer)
        except Exception as e:
            log(f"ERROR: Semgrep failed: {e}", log_buffer)

    return results

@app.post("/api/analyze")
async def analyze_code(input_data: CodeInput):
    logs = []
    log("START: Received analysis request.", logs)

    # 1. Save Files
    with open("temp_main.py", "w") as f:
        f.write(input_data.code)
    with open("requirements.txt", "w") as f:
        f.write(input_data.requirements)
    log("INFO: Source files saved to container.", logs)

    # 2. Parse AST
    log("INFO: Building Abstract Syntax Tree (AST)...", logs)
    try:
        tree = ast.parse(input_data.code)
    except SyntaxError as e:
        log(f"FATAL: Syntax Error in code: {e}", logs)
        return {"error": str(e), "logs": logs}

    routes = []
    functions = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            is_route = False
            route_path = ""
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and hasattr(decorator.func, 'attr'):
                    if decorator.func.attr in ['get', 'post', 'put', 'delete']:
                        is_route = True
                        if decorator.args:
                            route_path = decorator.args[0].value
            
            calls = []
            for subnode in ast.walk(node):
                if isinstance(subnode, ast.Call):
                    if isinstance(subnode.func, ast.Attribute):
                         func_name = subnode.func.attr
                         calls.append(func_name)

            functions[node.name] = {"is_route": is_route, "path": route_path, "calls": calls}
            if is_route:
                routes.append(node.name)
                log(f"DEBUG: Found Route {route_path} -> {node.name}", logs)

    # 3. Build Graph
    log("INFO: constructing Context Graph...", logs)
    graph_nodes = [{"data": {"id": "INTERNET", "color": "#00d2ff", "label": "Internet"}}]
    graph_edges = []
    
    for func_name in routes:
        path = functions[func_name]["path"]
        is_public = not (path.startswith("/admin") or path.startswith("/internal"))
        
        node_color = "#00C851" if not is_public else "#ffbb33"
        graph_nodes.append({"data": {"id": func_name, "color": node_color, "label": f"{path}"}} )
        
        if is_public:
            graph_edges.append({"data": {"source": "INTERNET", "target": func_name}})
            log(f"GRAPH: Edge added Internet -> {path}", logs)
        else:
            log(f"GRAPH: {path} is internal (No edge from Internet)", logs)

    # 4. Security Scan
    raw_vulns = run_security_scan(logs)

    # 5. Context Decision
    final_results = []
    deployment_blocked = False
    log("ANALYSIS: Correlating Vulnerabilities with Reachability Graph...", logs)

    for v in raw_vulns:
        status = "ALLOW"
        reason = "Not Reachable from Internet"
        
        if v['source'] == 'Semgrep':
            if "yaml" in v['id'].lower() or "deserialize" in v['id'].lower():
                 for r in routes:
                     path = functions[r]["path"]
                     if not (path.startswith("/admin") or path.startswith("/internal")):
                         if "load" in functions[r]["calls"]:
                             status = "BLOCK"
                             reason = f"CRITICAL: {path} is PUBLIC and executes Vulnerable Code!"
                             deployment_blocked = True
                             log(f"ALERT: BLOCKING DEPLOYMENT. Exploit path found: Internet -> {path}", logs)

        if v['source'] == 'Trivy' and "yaml" in v['pkg_name'].lower():
            for r in routes:
                path = functions[r]["path"]
                if not (path.startswith("/admin")):
                    if "load" in functions[r]["calls"]:
                        status = "BLOCK"
                        reason = f"CRITICAL: Vulnerable Library {v['pkg_name']} is used in PUBLIC route!"
                        deployment_blocked = True
                        log(f"ALERT: BLOCKING DEPLOYMENT. Vulnerable lib used in public route.", logs)

        final_results.append({
            "id": v['id'],
            "status": status,
            "reason": reason
        })

    log(f"COMPLETE: Final Decision is {'BLOCK' if deployment_blocked else 'ALLOW'}", logs)

    return {
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "vulnerabilities": final_results,
        "decision": "BLOCK" if deployment_blocked else "ALLOW",
        "logs": logs
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)


# ... (Keep all imports and logic)

# Serve the Main Dashboard (Scanner)
@app.get("/")
def serve_home():
    return FileResponse('app/static/index.html')

# Serve the Demo Page (Samples)
@app.get("/demo")
def serve_demo():
    return FileResponse('app/static/demo.html')

# ... (Keep the rest of the file exactly the same)