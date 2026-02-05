from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI(title="Agentic HoneyPot API")

API_KEY = "HONEY_POT_2026_KEY"
api_key_header = APIKeyHeader(name="x-api-key")

# ---------------- SECURITY ----------------

def verify_key(key: str = Depends(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ---------------- DATASET ----------------

SCAM_DATASET = [
    {"id": "UPI_001", "type": "UPI_FRAUD", "keywords": ["refund", "collect", "approve"]},
    {"id": "UPI_002", "type": "UPI_FRAUD", "keywords": ["sent by mistake", "reverse"]},
    {"id": "UPI_003", "type": "UPI_FRAUD", "keywords": ["scan", "qr", "cashback"]},

    {"id": "BANK_001", "type": "BANKING_FRAUD", "keywords": ["kyc", "expire", "block"]},
    {"id": "BANK_002", "type": "BANKING_FRAUD", "keywords": ["account frozen", "verify"]},
    {"id": "BANK_003", "type": "BANKING_FRAUD", "keywords": ["otp"]},

    {"id": "JOB_001", "type": "JOB_FRAUD", "keywords": ["work from home", "telegram", "task"]},
    {"id": "JOB_002", "type": "JOB_FRAUD", "keywords": ["registration fee", "offer letter"]},
    {"id": "JOB_003", "type": "JOB_FRAUD", "keywords": ["hr", "shortlisted"]},

    {"id": "LEGAL_001", "type": "LEGAL_THREAT", "keywords": ["courier", "customs", "illegal"]},
    {"id": "LEGAL_002", "type": "LEGAL_THREAT", "keywords": ["police", "fir", "aadhaar"]},

    {"id": "LOTTERY_001", "type": "LOTTERY_SCAM", "keywords": ["won", "lottery", "prize"]},
    {"id": "INVEST_001", "type": "INVESTMENT_SCAM", "keywords": ["crypto", "trading", "profit"]}
]

# ---------------- MODELS ----------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class Metadata(BaseModel):
    channel: Optional[str]
    language: Optional[str]
    locale: Optional[str]

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata]

# ---------------- API ----------------

@app.post("/honeypot/analyze")
def analyze(req: HoneypotRequest, key: str = Depends(verify_key)):

    msg = req.message.text.lower()
    scam_detected = False
    scam_type = "UNKNOWN"
    matched_id = None
    signals = []

    for scam in SCAM_DATASET:
        for kw in scam["keywords"]:
            if kw in msg:
                scam_detected = True
                scam_type = scam["type"]
                matched_id = scam["id"]
                signals.append(kw)

    money = re.findall(r"₹\d+|\$\d+", req.message.text)
    links = re.findall(r"https?://\S+", req.message.text)
    phone = re.findall(r"\b\d{10}\b", req.message.text)

    reply = "Can you explain that again? I am not clear."

    if scam_detected:
        reply = "Why is this required? I want to understand properly."

    return {
        "status": "success",
        "reply": reply,
        "analysis": {
            "sessionId": req.sessionId,
            "scamDetected": scam_detected,
            "scamType": scam_type,
            "matchedScamId": matched_id,
            "totalMessagesExchanged": len(req.conversationHistory) + 1,
            "extractedIntelligence": {
                "bankAccounts": [],
                "upis": [],
                "phishingLinks": links,
                "phoneNumbers": phone,
                "suspiciousKeywords": signals
            },
            "agentNotes": "Urgency or verification pressure observed" if scam_detected else "No strong indicators"
        }
    }