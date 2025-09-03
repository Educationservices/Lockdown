from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, uuid, time, asyncio

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
users = {}   # {username: {data: {}, "position": (x,y)}}
games = {}   # {game_id: {"user": username, "last_ping": float, "ws": WebSocket}}

# -------------------------
# User Endpoints
# -------------------------
@app.get("/usercount")
async def user_count():
    return {"count": len(users)}

@app.get("/userlist")
async def user_list():
    return {"users": list(users.keys())}

@app.get("/view")
async def view_user(user: str):
    if user not in users:
        return {"valid": False, "reason": "User not found"}
    for gid, g in games.items():
        if g["user"] == user and time.time() - g["last_ping"] <= 10:
            return {"valid": True, "game_id": gid}
    return {"valid": False}

# -------------------------
# Game start
# -------------------------
@app.get("/gamestart")
async def game_start(user: str):
    users[user] = {"data": {}, "position": (0, 0)}
    game_id = str(uuid.uuid4())
    games[game_id] = {"user": user, "last_ping": time.time(), "ws": None}
    return {"game_id": game_id, "user": user}

# -------------------------
# WebSocket for game pings + updates
# -------------------------
@app.websocket("/game/{game_id}")
async def game_ws(websocket: WebSocket, game_id: str):
    await websocket.accept()

    if game_id not in games:
        await websocket.send_json({"error": "invalid id"})
        await websocket.close()
        return

    games[game_id]["ws"] = websocket
    user = games[game_id]["user"]

    # Refresh last_ping right on connect
    games[game_id]["last_ping"] = time.time()

    # Confirm connection
    await websocket.send_json({"status": "connected", "id": game_id})

    try:
        while True:
            # Try JSON first
            try:
                msg = await websocket.receive_json()
            except Exception:
                raw = await websocket.receive_text()
                msg = {"type": raw}

            print("Got message from", user, ":", msg)

            games[game_id]["last_ping"] = time.time()

            if msg.get("type") == "ping":
                await websocket.send_json({"status": "pong", "id": game_id})

            elif msg.get("type") == "pos":
                x, y = msg.get("x"), msg.get("y")
                users[user]["position"] = (x, y)
                await websocket.send_json({"status": "pos_updated", "x": x, "y": y})

    except WebSocketDisconnect:
        print(f"WebSocket closed for user {user}")
        if game_id in games:
            del games[game_id]
        if user in users:
            del users[user]



# -------------------------
# Auto cleanup expired sessions
# -------------------------
async def cleanup_task():
    while True:
        now = time.time()
        for gid, g in list(games.items()):
            if now - g["last_ping"] > 10:  # expired
                user = g["user"]
                if g["ws"]:
                    await g["ws"].close()
                del games[gid]
                if user in users:
                    del users[user]
        await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_task())

# -------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
