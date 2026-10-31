import os
import sys
from fastapi import FastAPI

# Add folder paths so Python can locate your internal modules
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_DIR, "q2"))
sys.path.append(os.path.join(CURRENT_DIR, "q3"))
sys.path.append(os.path.join(CURRENT_DIR, "q4"))

# Import apps from your exact filenames
from q2.main import app as q2_app, get_agent_card       # q2/main.py
from q3.mailroom import app as q3_app                   # q3/mailroom.py
from q4.incident_agent import app as q4_app             # q4/incident_agent.py

# Create the top-level unified server
app = FastAPI(title="TDS GA3 Combined Service")

# 1. Q2 Origin Discovery: Grader strictly checks GET /.well-known/agent-card.json at root origin
@app.get("/.well-known/agent-card.json")
def origin_agent_card():
    return get_agent_card()

# 2. Mount Q2 under /a2a
app.mount("/a2a", q2_app)

# 3. Mount Q3 under /mailroom
app.mount("/mailroom", q3_app)

# 4. Mount Q4 under root so it serves /v2/incidents directly
app.mount("/v2", q4_app)

# 5. Root Health Check
@app.get("/")
def health():
    return {"status": "ok", "service": "GA3 Multi-Agent Runner"}
