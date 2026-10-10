"""Realtime event stream over WebSocket.

The collector publishes each stored event to Redis `events:all`; this endpoint
authenticates the operator by JWT (query param), subscribes, and relays the
JSON messages to the dashboard. See docs/DESIGN.md §6.3.
"""
from __future__ import annotations

import jwt
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from app.security.jwt import decode_token
from app.services.telemetry import CHANNEL_ALL

router = APIRouter()


@router.websocket("/api/v1/ws")
async def ws_events(websocket: WebSocket, token: str = Query(...)):
    # Authenticate before accepting (JWT in query param — WS has no auth header).
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise ValueError("wrong token type")
    except (jwt.PyJWTError, ValueError):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    redis = websocket.app.state.redis
    pubsub = redis.pubsub()
    await pubsub.subscribe(CHANNEL_ALL)
    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=30)
            if msg and msg.get("type") == "message":
                await websocket.send_text(msg["data"])
            else:
                # Periodic keepalive; also surfaces client disconnects promptly.
                await websocket.send_text('{"type":"ping"}')
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - connection reset etc.
        pass
    finally:
        try:
            await pubsub.unsubscribe(CHANNEL_ALL)
            await pubsub.aclose()
        except Exception:  # noqa: BLE001
            pass
