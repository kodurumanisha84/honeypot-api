from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List
import re

app = FastAPI(title="Agentic HoneyPot API")

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

# ---------------- SCAM DATABASE ----------------
SCAMS = {
     # 🔴 BANKING & PAYMENT
    "BANKING_FRAUD": {
        "keywords": ["bank", "kyc", "account", "otp", "blocked"],
        "replies": [
            "Sir I am poor man 😢 why my account only?",
            "My ATM card is lost since 2019… still problem?",
            "If account blocks, salary will come or not?"
        ]
    },

    "UPI_FRAUD": {
        "keywords": ["upi", "qr", "scan", "refund", "collect"],
        "replies": [
            "Oh no 😰 I just had tea… will my money go before dinner?",
            "UPI means government thing right? I am scared now.",
            "If I scan QR will my phone explode? 😟"
        ]
    },

    # 🟡 SOCIAL MEDIA
    "INSTAGRAM_SCAM": {
        "keywords": ["instagram", "blue tick", "verified", "account disabled"],
        "replies": [
            "Blue tick will make me famous? 😎",
            "If account disabled, my reels gone?",
            "Can I get followers also with this?"
        ]
    },

    "FACEBOOK_SCAM": {
        "keywords": ["facebook", "meta", "page blocked"],
        "replies": [
            "My Facebook is only memes 😭 still blocked?",
            "Is this from Meta officially?",
            "Can I recover my old photos?"
        ]
    },

    "WHATSAPP_SCAM": {
        "keywords": ["whatsapp", "code", "six digit", "verify"],
        "replies": [
            "Why WhatsApp sending code to you?",
            "If hacked, my chats gone?",
            "Can I reinstall WhatsApp?"
        ]
    },

    # 🔵 CONTENT CREATOR
    "YOUTUBE_SCAM": {
        "keywords": ["youtube", "copyright", "strike", "monetization"],
        "replies": [
            "Copyright strike?? I have only 3 subscribers 😭",
            "I upload memes only sir… still problem?",
            "If channel deletes, will videos cry?"
        ]
    },

    # 🟠 DELIVERY & E-COMMERCE
    "DELIVERY_SCAM": {
        "keywords": ["parcel", "courier", "customs", "delivery failed"],
        "replies": [
            "Parcel? I didn’t order anything 🤔",
            "Is it Amazon or Flipkart?",
            "Can delivery boy call directly?"
        ]
    },

    "ECOMMERCE_SCAM": {
        "keywords": ["amazon", "flipkart", "order cancelled", "refund"],
        "replies": [
            "Refund already credited or pending?",
            "Why refund needs OTP?",
            "Can I check in app?"
        ]
    },

    # 💔 RELATIONSHIP
    "ROMANCE_SCAM": {
        "keywords": ["love", "darling", "marriage", "trust me"],
        "replies": [
            "You love me so fast? 😳",
            "Marriage already? We didn’t fight yet!",
            "Can you send photo with today’s newspaper?"
        ]
    },

    # 🟣 TECH SUPPORT
    "TECH_SUPPORT_SCAM": {
        "keywords": ["microsoft", "virus", "support", "hacked"],
        "replies": [
            "Virus? Laptop already slow since 2015 😭",
            "If hacked, will my photos leak?",
            "Can I just shut down laptop?"
        ]
    },

    # 🟢 GOVERNMENT
    "GOVERNMENT_SCAM": {
        "keywords": ["aadhar", "pan", "income tax", "subsidy"],
        "replies": [
            "Aadhar already linked everywhere sir 😵",
            "Government calling on WhatsApp?",
            "Will subsidy stop if I ignore?"
        ]
    },

    # 🟤 LEGAL & THREATS
    "LEGAL_SCAM": {
        "keywords": ["police", "court", "fir", "legal notice"],
        "replies": [
            "Police?? 😭 I did nothing wrong.",
            "Can we solve without court?",
            "Should I tell my parents?"
        ]
    },

    # 💰 MONEY MAKING
    "LOTTERY_SCAM": {
        "keywords": ["lottery", "prize", "won"],
        "replies": [
            "I never bought ticket… still lucky? 😂",
            "Prize is cash or cooker?",
            "Can prize come by COD?"
        ]
    },

    "INVESTMENT_SCAM": {
        "keywords": ["crypto", "investment", "profit", "trading"],
        "replies": [
            "Profit guaranteed means 100% or 200%?",
            "If loss happens, will you return money?",
            "Can I invest ₹500 first?"
        ]
    },

    # 🧠 JOB & EDUCATION
    "JOB_SCAM": {
        "keywords": ["job", "work from home", "registration fee"],
        "replies": [
            "Why job asking money first?",
            "Is company registered in India?",
            "Can I pay after salary?"
        ]
    },

    "EDUCATION_SCAM": {
        "keywords": ["admission", "degree", "certificate"],
        "replies": [
            "Degree without exam really possible?",
            "Is this UGC approved?",
            "Will college verify later?"
        ]
    }

}

# ---------------- HELPERS ----------------
def detect_scam_type(text: str) -> str:
    text = text.lower()
    for scam_type, data in SCAMS.items():
        for kw in data["keywords"]:
            if kw in text:
                return scam_type
    return "UNKNOWN"

def get_agent_reply(scam_type: str, turn: int) -> str:
    if scam_type == "UNKNOWN":
        return "I am confused 😕 can you explain again?"

    replies = SCAMS[scam_type]["replies"]
    index = min(turn - 1, len(replies) - 1)
    return replies[index]

def extract_intelligence(text: str) -> dict:
    return {
        "phoneNumbers": re.findall(r"\b\d{10}\b", text),
        "emailIds": re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z.-]+\.[a-zA-Z]{2,}", text),
        "upiIds": re.findall(r"\b[\w.-]+@[\w.-]+\b", text),
        "phishingLinks": re.findall(r"https?://\S+", text),
        "cryptoWallets": re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text),
        "governmentIds": {
            "pan": re.findall(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text),
            "aadhar": re.findall(r"\b\d{4}\s\d{4}\s\d{4}\b", text)
        },
        "caseOrOrderNumbers": re.findall(r"\b[A-Z0-9]{6,}\b", text),
        "mentionedBanks": [b for b in ["sbi", "hdfc", "icici", "axis"] if b in text.lower()],
        "urgencySignals": [u for u in ["urgent", "today", "immediately", "within 1 hour"] if u in text.lower()],
        "socialPlatforms": [p for p in ["youtube", "instagram", "whatsapp", "facebook"] if p in text.lower()]
    }

# ---------------- API ----------------
@app.post("/honeypot/analyze")
def analyze(req: HoneypotRequest, key: str = Depends(verify_key)):
    turn = len(req.conversationHistory) + 1
    text = req.message.text

    scam_type = detect_scam_type(text)
    reply = get_agent_reply(scam_type, turn)
    intelligence = extract_intelligence(text)

    return {
        "status": "success",
        "reply": reply,
        "analysis": {
            "scamType": scam_type,
            "turn": turn,
            "extractedIntelligence": intelligence,
            "agentNote": f"Deterministic victim-style reply for {scam_type}"
        }
    }
