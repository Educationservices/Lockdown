from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import uuid, time

app = FastAPI()

# In-memory storage
users = {}   # {username: {data: {}}}
games = {}   # {id: {"user": str, "last_ping": float}}

# -------------------------
# User Endpoints
# -------------------------
@app.get("/usercount")
async def user_count():
    return {"count": len(users)}

@app.get("/userlist")
async def user_list():
    return {"users": list(users.keys())}

@app.post("/user")
async def update_user(user: str, request: Request):
    body = await request.json()
    if user not in users:
        users[user] = {"data": {}}
    users[user]["data"].update(body)
    return {"message": "User data updated", "user": user, "data": users[user]}

@app.get("/view")
async def view_user(user: str):
    if user not in users:
        return {"valid": False, "reason": "User not found"}
    # Check if they have an active game session
    for gid, g in games.items():
        if g["user"] == user:
            if time.time() - g["last_ping"] <= 10:
                return {"valid": True, "game_id": gid}
    return {"valid": False}

# -------------------------
# Game Endpoints
# -------------------------
@app.post("/gamestart")
async def game_start(user: str):
    if user not in users:
        users[user] = {"data": {}}
    game_id = str(uuid.uuid4())
    games[game_id] = {"user": user, "last_ping": time.time()}
    return {"game_id": game_id, "user": user}

@app.post("/game")
async def game_ping(id: str):
    if id in games:
        games[id]["last_ping"] = time.time()
        return {"status": "pong", "id": id}
    return {"status": "invalid id"}

# Background cleanup (optional: call periodically)
@app.get("/cleanup")
async def cleanup():
    expired = []
    now = time.time()
    for gid, g in list(games.items()):
        if now - g["last_ping"] > 10:
            expired.append(gid)
            del games[gid]
    return {"expired_games": expired}

# -------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
