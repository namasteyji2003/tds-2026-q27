import time
from collections import defaultdict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import logging

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)

# Logging setup
logging.basicConfig(level=logging.INFO)

# ----------------------------
# Rate Limiting Config
# ----------------------------
MAX_REQUESTS_PER_MINUTE = 26
BURST_LIMIT = 13
REFILL_RATE = MAX_REQUESTS_PER_MINUTE / 60  # tokens per second

# Token bucket store per user/IP
rate_limit_store = defaultdict(lambda: {
    "tokens": BURST_LIMIT,
    "last_refill": time.time()
})

# ----------------------------
# Request Model
# ----------------------------
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

# ----------------------------
# Rate Limiting Logic
# ----------------------------
def check_rate_limit(identifier: str):

    bucket = rate_limit_store[identifier]
    current_time = time.time()

    # Refill tokens
    elapsed = current_time - bucket["last_refill"]
    refill_tokens = elapsed * REFILL_RATE
    bucket["tokens"] = min(BURST_LIMIT, bucket["tokens"] + refill_tokens)
    bucket["last_refill"] = current_time

    if bucket["tokens"] < 1:
        return False

    bucket["tokens"] -= 1
    return True

# ----------------------------
# Security Endpoint
# ----------------------------
@app.post("/validate")
async def validate(request: Request, payload: SecurityRequest):

    identifier = payload.userId or request.client.host

    if not identifier:
        raise HTTPException(status_code=400, detail="Invalid request")

    allowed = check_rate_limit(identifier)

    if not allowed:
        logging.warning(f"Rate limit exceeded for {identifier}")

        retry_after = 60

        return JSONResponse(
            status_code=429,
            content={
                "blocked": True,
                "reason": "Rate limit exceeded. Try again later.",
                "sanitizedOutput": None,
                "confidence": 0.99
            },
            headers={"Retry-After": str(retry_after)}
        )

    # If allowed
    sanitized = payload.input.strip()

    return {
        "blocked": False,
        "reason": "Input passed all security checks",
        "sanitizedOutput": sanitized,
        "confidence": 0.95
    }
