
from fastapi import FastAPI
from pydantic import BaseModel

from detection.rules import analyze_event
from detection.mitre_mapping import map_mitre_technique


app = FastAPI(
    title="AI Cyber Threat Analyzer",
    description="API for cybersecurity event analysis",
    version="1.0.0",
)


class SecurityEvent(BaseModel):
    process_name: str
    command_line: str = ""
    parent_process: str = ""


@app.get("/")
def home():
    return {
        "message": "AI Cyber Threat Analyzer API",
        "status": "online",
    }


@app.post("/analyze")
def analyze_security_event(event: SecurityEvent):
    event_data = event.model_dump()

    result = analyze_event(event_data)

    mitre = map_mitre_technique(event_data, result)
    
    return {
        "event": event_data,
        "detection": result,
        "mitre_attack": mitre,
    }
