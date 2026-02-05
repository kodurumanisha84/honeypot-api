from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List
import random, re

app = FastAPI(title="Universal Scam Detection & Honeypot API")

# ---------------- SECURITY ----------------
API_KEY = "HONEY_POT_2026_KEY"
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

def verify_key(key: str = Depends(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ---------------- MODELS ----------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []

# ---------------- UNIVERSAL SCAM VECTORS ----------------
SCAM_VECTORS = {
    "FINANCIAL": ["bank", "otp", "upi", "refund", "account", "blocked"],
    "JOB_EDU": ["job", "fee", "registration", "degree", "exam"],
    "ECOMMERCE": ["delivery", "order", "amazon", "flipkart"],
    "RELATIONSHIP": ["love", "marriage", "trust"],
    "AUTHORITY": ["police", "court", "customs", "trai"],
    "TECH": ["virus", "support", "microsoft", "hacked"],
    "INVESTMENT": ["crypto", "trading", "profit"],
    "GOVERNMENT": ["aadhaar", "pan", "subsidy", "tax"],
    "MEDICAL": ["hospital", "emergency", "accident"],
    "BUSINESS": ["invoice", "vendor", "payment change"]
}

INTENT_VECTORS = {
    "MONEY": ["pay", "transfer", "fee", "send"],
    "CREDENTIAL": ["otp", "pin", "password"],
    "THREAT": ["blocked", "arrest", "freeze"],
    "URGENCY": ["urgent", "immediately", "minutes"]
}

RESPONSE_MODES = [
    "CONFUSED", "FEARFUL", "LOGICAL", "TIME_WASTER", "OVER_SHARING"
]

# ---------------- DETECTION ----------------
def detect_vectors(text: str):
    text = text.lower()
    return [v for v, kws in SCAM_VECTORS.items() if any(k in text for k in kws)]

def detect_intents(text: str):
    text = text.lower()
    return [i for i, kws in INTENT_VECTORS.items() if any(k in text for k in kws)]

# ---------------- RESPONSE ENGINE ----------------
def generate_response(vectors, intents):
    mode = random.choice(RESPONSE_MODES)

    money = random.choice(["₹499", "₹1,000", "₹2,500"])
    time = random.choice(["today", "tomorrow", "month end"])
    device = random.choice(["old phone", "office laptop", "borrowed mobile"])

    if mode == "CONFUSED":
        return "I am not understanding 😕 can you explain again slowly?"

    if mode == "FEARFUL":
        return f"If this happens, my {money} salary will still come on {time} or not?"

    if mode == "LOGICAL":
        return "Official messages usually come inside app, why this is different?"

    if mode == "TIME_WASTER":
        return f"My battery is low on {device} 😬 please wait 5 minutes."

    if mode == "OVER_SHARING":
        return "Earlier also similar message came but nothing happened."

    return "Please explain again."

# ---------------- INTELLIGENCE ----------------
def extract_intelligence(text: str):
    return {
        "phones": re.findall(r"\b\d{10}\b", text),
        "emails": re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z.-]+\.[a-zA-Z]{2,}", text),
        "upi": re.findall(r"\b[\w.-]+@[\w.-]+\b", text),
        "links": re.findall(r"https?://\S+", text)
    }

# ---------------- API ----------------
@app.post("/honeypot/analyze")
def analyze(req: HoneypotRequest, key: str = Depends(verify_key)):
    text = req.message.text

    vectors = detect_vectors(text)
    intents = detect_intents(text)

    response = generate_response(vectors, intents)
    intelligence = extract_intelligence(text)

    return {
        "status": "success",
        "reply": response,
        "analysis": {
            "vectors": vectors or ["EMERGING_OR_UNKNOWN"],
            "intents": intents,
            "turn": len(req.conversationHistory) + 1,
            "extractedIntelligence": intelligence,
            "agentNote": "Vector-based universal scam handling"
        }
    }
