"""Request body size limit for every endpoint except ingestion.

The ingestion endpoint enforces its own (larger, configurable) limit while it
streams the upload. Every other endpoint takes small JSON bodies, so anything
above ``max_bytes`` is refused. The bytes are counted as they arrive, so a
missing or false Content-Length header does not bypass the limit.
"""

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import error_body

DEFAULT_MAX_BODY_BYTES = 1024 * 1024
EXEMPT_PATHS = ("/api/v1/ingestion/batches",)


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = DEFAULT_MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length", b"")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return

        received = 0
        rejected = False

        async def limited_receive() -> Message:
            # Raising here would not work: FastAPI turns any error while reading
            # the body into a generic 400. Instead, answer 413 ourselves and tell
            # the application the client went away, so it stops reading.
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    rejected = True
                    await self._reject(send)
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            if not rejected:  # the 413 has already been sent; drop anything else
                await send(message)

        await self.app(scope, limited_receive, guarded_send)

    async def _reject(self, send: Send) -> None:
        body = json.dumps(
            error_body("payload_too_large", f"Request body exceeds {self.max_bytes} bytes.")
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
