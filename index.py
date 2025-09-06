from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, uuid, time, asyncio, json
from typing import Dict, Set

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage - RESTRUCTURED FOR MULTIPLAYER
users = {}      # {username: {"position": (x,y), "data": {}, "current_room": room_id}}
rooms = {}      # {room_id: {"players": Set[username], "websockets": Dict[username, WebSocket], "last_activity": float}}
user_to_room = {}  # {username: room_id} - quick lookup

# -------------------------
# User Endpoints
# -------------------------
@app.get("/usercount")
async def user_count():
    return {"count": len(users)}

@app.get("/userlist")
async def user_list():
    return {"users": list(users.keys())}

@app.get("/rooms")
async def room_list():
    return {
        "rooms": {
            room_id: {
                "player_count": len(room_data["players"]),
                "players": list(room_data["players"])
            }
            for room_id, room_data in rooms.items()
        }
    }

@app.get("/view")
async def view_user(user: str):
    if user not in users:
        return {"valid": False, "reason": "User not found"}
    
    if user in user_to_room:
        room_id = user_to_room[user]
        if room_id in rooms and time.time() - rooms[room_id]["last_activity"] <= 30:
            return {"valid": True, "room_id": room_id}
    
    return {"valid": False}

# -------------------------
# Room Management
# -------------------------
@app.get("/create_room")
async def create_room(user: str, room_name: str = None):
    """Create a new room"""
    # Initialize user if not exists
    if user not in users:
        users[user] = {"data": {}, "position": (0, 0)}
    
    room_id = room_name if room_name else str(uuid.uuid4())
    
    # If room already exists, just join it
    if room_id in rooms:
        return await join_room_logic(user, room_id)
    
    # Create new room
    rooms[room_id] = {
        "players": {user},
        "websockets": {},
        "last_activity": time.time(),
        "created_by": user
    }
    user_to_room[user] = room_id
    users[user]["current_room"] = room_id
    
    return {"room_id": room_id, "user": user, "action": "created"}

@app.get("/join_room")
async def join_room(user: str, room_id: str):
    """Join an existing room"""
    if room_id not in rooms:
        return {"error": "Room not found"}
    
    return await join_room_logic(user, room_id)

async def join_room_logic(user: str, room_id: str):
    # Initialize user if not exists
    if user not in users:
        users[user] = {"data": {}, "position": (0, 0)}
    
    # Remove from old room if exists
    if user in user_to_room:
        old_room = user_to_room[user]
        if old_room in rooms:
            rooms[old_room]["players"].discard(user)
            if user in rooms[old_room]["websockets"]:
                del rooms[old_room]["websockets"][user]
            # Delete empty rooms
            if not rooms[old_room]["players"]:
                del rooms[old_room]
    
    # Add to new room
    rooms[room_id]["players"].add(user)
    user_to_room[user] = room_id
    users[user]["current_room"] = room_id
    rooms[room_id]["last_activity"] = time.time()
    
    return {
        "room_id": room_id, 
        "user": user, 
        "action": "joined",
        "players_in_room": list(rooms[room_id]["players"])
    }

# -------------------------
# Broadcasting Helper
# -------------------------
async def broadcast_to_room(room_id: str, message: dict, exclude_user: str = None):
    """Send message to all players in a room except excluded user"""
    if room_id not in rooms:
        return
    
    for username, websocket in rooms[room_id]["websockets"].items():
        if username != exclude_user:
            try:
                await websocket.send_json(message)
            except:
                # Handle disconnected websockets
                pass

# -------------------------
# WebSocket for multiplayer game
# -------------------------
@app.websocket("/game/{room_id}")
async def game_ws(websocket: WebSocket, room_id: str, user: str):
    await websocket.accept()
    
    # Validate room and user
    if room_id not in rooms:
        await websocket.send_json({"error": "Room not found"})
        await websocket.close()
        return
    
    if user not in rooms[room_id]["players"]:
        await websocket.send_json({"error": "User not in this room"})
        await websocket.close()
        return
    
    # Register websocket
    rooms[room_id]["websockets"][user] = websocket
    rooms[room_id]["last_activity"] = time.time()
    
    # Send connection confirmation + current room state
    await websocket.send_json({
        "status": "connected", 
        "room_id": room_id,
        "your_username": user,
        "players_in_room": list(rooms[room_id]["players"]),
        "all_positions": {
            u: users[u]["position"] for u in rooms[room_id]["players"] if u in users
        }
    })
    
    # Notify others that user joined
    await broadcast_to_room(room_id, {
        "type": "player_joined",
        "user": user,
        "position": users[user]["position"]
    }, exclude_user=user)
    
    try:
        while True:
            try:
                msg = await websocket.receive_json()
            except Exception:
                raw = await websocket.receive_text()
                msg = {"type": raw}
            
            print(f"Room {room_id} - {user}: {msg}")
            rooms[room_id]["last_activity"] = time.time()
            
            if msg.get("type") == "ping":
                await websocket.send_json({"status": "pong", "room_id": room_id})
            
            elif msg.get("type") == "pos":
                x, y = msg.get("x"), msg.get("y")
                users[user]["position"] = (x, y)
                
                # Confirm to sender
                await websocket.send_json({"status": "pos_updated", "x": x, "y": y})
                
                # Broadcast to all other players in room
                await broadcast_to_room(room_id, {
                    "type": "player_moved",
                    "user": user,
                    "x": x,
                    "y": y
                }, exclude_user=user)
            
            elif msg.get("type") == "chat":
                message = msg.get("message", "")
                timestamp = time.time()
                
                # Broadcast chat to everyone in room INCLUDING sender
                chat_msg = {
                    "type": "chat_message",
                    "user": user,
                    "message": message,
                    "timestamp": timestamp
                }
                await websocket.send_json(chat_msg)  # Send to sender
                await broadcast_to_room(room_id, chat_msg, exclude_user=user)  # Send to others
            
            elif msg.get("type") == "game_event":
                # Handle custom game events and broadcast them
                event_data = msg.get("data", {})
                event_msg = {
                    "type": "game_event",
                    "user": user,
                    "event": msg.get("event"),
                    "data": event_data,
                    "timestamp": time.time()
                }
                await broadcast_to_room(room_id, event_msg)  # Send to everyone including sender
    
    except WebSocketDisconnect:
        pass
    finally:
        # Clean up on disconnect
        print(f"User {user} disconnected from room {room_id}")
        
        # Remove websocket
        if room_id in rooms and user in rooms[room_id]["websockets"]:
            del rooms[room_id]["websockets"][user]
        
        # Notify others that user left
        await broadcast_to_room(room_id, {
            "type": "player_left",
            "user": user
        })
        
        # Remove player from room
        if room_id in rooms:
            rooms[room_id]["players"].discard(user)
            # Delete empty rooms
            if not rooms[room_id]["players"]:
                del rooms[room_id]
        
        # Clean up user mappings
        if user in user_to_room:
            del user_to_room[user]

# -------------------------
# Auto cleanup expired rooms
# -------------------------
async def cleanup_task():
    while True:
        now = time.time()
        for room_id, room_data in list(rooms.items()):
            if now - room_data["last_activity"] > 60:  # 1 minute timeout
                print(f"Cleaning up inactive room: {room_id}")
                # Close all websockets in room
                for username, ws in room_data["websockets"].items():
                    try:
                        await ws.close()
                    except:
                        pass
                    if username in user_to_room:
                        del user_to_room[username]
                del rooms[room_id]
        await asyncio.sleep(10)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_task())

# -------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
