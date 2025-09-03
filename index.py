from fastapi import FastAPI, Request
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
users = {}   # {username: {data: {}}}
games = {}   # {game_id: {"user": username, "last_ping": float}}

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
    for gid, g in games.items():
        if g["user"] == user and time.time() - g["last_ping"] <= 10:
            return {"valid": True, "game_id": gid}
    return {"valid": False}

# -------------------------
# Game Endpoints
# -------------------------
@app.post("/gamestart")
async def game_start(user: str):
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

# -------------------------
# Automatic cleanup task
# -------------------------
async def cleanup_task():
    while True:
        now = time.time()
        for gid, g in list(games.items()):
            if now - g["last_ping"] > 10:
                username = g["user"]
                del games[gid]
                if username in users:
                    del users[username]
        await asyncio.sleep(1)  # run every 1 second

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_task())

# -------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
