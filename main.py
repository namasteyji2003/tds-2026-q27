from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from collections import defaultdict, deque
import time
import logging

app = FastAPI()

# -----------------------------
# Configuration
# -----------------------------
RATE_LIMIT = 26           # max per minute
BURST_LIMIT = 13          # max immediate burst
WINDOW_SIZE = 60          # seconds

# Store request timestamps per user/IP
request_store = defaultdict(deque)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")

# -----------------------------
# Request Model
# -----------------------------
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


# -----------------------------
# Rate Limiting Logic
# -----------------------------
def check_rate_limit(identifier: str):
    now = time.time()
    window_start = now - WINDOW_SIZE

    timestamps = request_store[identifier]

    # Remove expired timestamps
    while timestamps and timestamps[0] < window_start:
        timestamps.popleft()

    # Check burst first (rapid hits)
    if len(timestamps) >= BURST_LIMIT and (now - timestamps[-BURST_LIMIT]) < 1:
        retry_after = 1
        return False, retry_after

    # Check total per minute
    if len(timestamps) >= RATE_LIMIT:
        retry_after = int(WINDOW_SIZE - (now - timestamps[0]))
        return False, retry_after

    timestamps.append(now)
    return True, None


# -----------------------------
# API Endpoint
# -----------------------------
@app.post("/security/validate")
async def validate_security(data: SecurityRequest, request: Request):

    # Basic input validation
    if not data.userId or not data.input:
        raise HTTPException(status_code=400, detail="Invalid request format")

    # Combine userId + IP for stricter tracking
    client_ip = request.client.host
    identifier = f"{data.userId}:{client_ip}"

    allowed, retry_after = check_rate_limit(identifier)

    if not allowed:
        logger.warning(f"Rate limit exceeded for {identifier}")

        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "blocked": True,
                "reason": "Rate limit exceeded",
                "sanitizedOutput": None,
                "confidence": 0.99
            }
        )

    # If passed
    logger.info(f"Request allowed for {identifier}")

    return {
        "blocked": False,
        "reason": "Input passed all security checks",
        "sanitizedOutput": data.input.strip(),
        "confidence": 0.95
    }


# -----------------------------
# Global Exception Handler
# -----------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unexpected validation error")
    return JSONResponse(
        status_code=500,
        content={
            "blocked": True,
            "reason": "Security validation failed",
            "confidence": 0.75
        }
    )
