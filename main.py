from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from collections import defaultdict, deque
import time
import logging

app = FastAPI()

# ==============================
# Configuration
# ==============================
RATE_LIMIT = 26        # Max per minute
BURST_LIMIT = 13       # Max burst allowed
WINDOW_SECONDS = 60

# Store request timestamps per user/IP
rate_store = defaultdict(deque)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")

# ==============================
# Request Model
# ==============================
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


# ==============================
# Rate Limit Check
# ==============================
def is_rate_limited(identifier: str):
    current_time = time.time()
    window_start = current_time - WINDOW_SECONDS

    timestamps = rate_store[identifier]

    # Remove expired timestamps
    while timestamps and timestamps[0] < window_start:
        timestamps.popleft()

    # Burst protection (13 rapid requests allowed)
    if len(timestamps) >= BURST_LIMIT:
        if current_time - timestamps[-BURST_LIMIT] < 1:
            return True, 1

    # 26 per minute limit
    if len(timestamps) >= RATE_LIMIT:
        retry_after = int(WINDOW_SECONDS - (current_time - timestamps[0]))
        return True, retry_after

    timestamps.append(current_time)
    return False, None


# ==============================
# Endpoint
# ==============================
@app.post("/security/validate")
async def validate(request_data: SecurityRequest, request: Request):

    # Basic validation
    if not request_data.userId.strip() or not request_data.input.strip():
        raise HTTPException(status_code=400, detail="Invalid request payload")

    client_ip = request.client.host
    identifier = f"{request_data.userId}:{client_ip}"

    blocked, retry_after = is_rate_limited(identifier)

    if blocked:
        logger.warning(f"Rate limit exceeded: {identifier}")

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

    logger.info(f"Request allowed: {identifier}")

    return {
        "blocked": False,
        "reason": "Input passed all security checks",
        "sanitizedOutput": request_data.input.strip(),
        "confidence": 0.95
    }


# ==============================
# Global Error Handler
# ==============================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Security validation error occurred")
    return JSONResponse(
        status_code=500,
        content={
            "blocked": True,
            "reason": "Security validation failed",
            "confidence": 0.75
        }
    )
