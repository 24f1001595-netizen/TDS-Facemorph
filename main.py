import os
import sys
from fastapi import FastAPI, Request

# Add subfolder paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_DIR, "q2"))
sys.path.append(os.path.join(CURRENT_DIR, "q3"))
sys.path.append(os.path.join(CURRENT_DIR, "q4"))

# Import apps from your files
from q2.main import app as q2_app, get_agent_card       # q2/main.py
from q3.mailroom import app as q3_app                   # q3/mailroom.py
from q4.incident_agent import app as q4_app             # q4/incident_agent.py

# Create the top-level server (redirect_slashes=False prevents HTTP 307 redirects)
app = FastAPI(title="TDS GA3 Combined Service", redirect_slashes=False)

# 1. Q2 Origin Discovery (Grader requires GET /.well-known/agent-card.json at the origin)
@app.get("/.well-known/agent-card.json")
def origin_agent_card():
    return get_agent_card()

# 2. Q2 A2A Agent
app.mount("/a2a", q2_app)

# 3. Q3 Safe AI Mailroom Forwarder (Catches both /mailroom and /mailroom/ cleanly)
@app.api_route("/mailroom", methods=["GET", "POST"])
@app.api_route("/mailroom/", methods=["GET", "POST"])
async def forward_mailroom(request: Request):
    return await q3_app(request.scope, request.receive, request._send)

# 4. Q4 Incident Agent (Mounted directly at root so /v2/incidents is NOT doubled)
app.mount("", q4_app)

# 5. Root Health Check
@app.get("/")
def health():
    return {"status": "ok", "service": "GA3 Multi-Agent Runner"}
