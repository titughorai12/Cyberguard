import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException


_requests = defaultdict(list)
_lock = Lock()


def check_rate_limit(
    client_id: str,
    limit: int,
) -> None:
    """Allow a client only a limited number of requests per minute."""

    if limit <= 0:
        return

    now = time.time()
    window_start = now - 60

    with _lock:
        request_times = _requests[client_id]

        request_times[:] = [
            request_time
            for request_time in request_times
            if request_time > window_start
        ]

        if len(request_times) >= limit:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again later.",
            )

        request_times.append(now)
