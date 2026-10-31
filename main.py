from fastapi import FastAPI
import sys
import os

# Add subfolders to system path so Python can import their modules
sys.path.append(os.path.join(os.path.dirname(__file__), "q2"))
sys.path.append(os.path.join(os.path.dirname(__file__), "q3"))
sys.path.append(os.path.join(os.path.dirname(__file__), "q4"))

# Import the FastAPI apps or routers from your folders
# (Adjust module names if your files are named differently, e.g. main vs mailroom vs incident_agent)
from main import app as q2_app, get_agent_card  # Q2 main.py
from mailroom import app as q3_app             # Q3 mailroom.py
from incident_agent import app as q4_app       # Q4 incident_agent.py

app = FastAPI(title="TDS GA3 Combined Agents")

# Q2: Discovery Card at origin level (Grader strictly checks /.well-known/agent-card.json)
@app.get("/.well-known/agent-card.json")
def origin_agent_card():
    return get_agent_card()

# Mount agents under distinct paths
app.mount("/a2a", q2_app)
app.mount("/mailroom", q3_app)
app.mount("/v2", q4_app) # Routes Q4 directly to /v2/incidents
