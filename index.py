@app.websocket("/game/{game_id}")
async def game_ws(websocket: WebSocket, game_id: str):
    await websocket.accept()
    if game_id not in games:
        await websocket.send_json({"error": "invalid id"})
        await websocket.close()
        return

    games[game_id]["ws"] = websocket
    user = games[game_id]["user"]
    games[game_id]["last_ping"] = time.time()

    # Send connection confirmation
    await websocket.send_json({"status": "connected", "id": game_id})

    try:
        while True:
            # Try to receive message - handle both JSON and text
            try:
                msg = await websocket.receive_json()
            except ValueError:
                # If JSON parsing fails, try as text
                try:
                    raw = await websocket.receive_text()
                    msg = {"type": raw}
                except WebSocketDisconnect:
                    # Client disconnected while receiving text
                    break
            except WebSocketDisconnect:
                # Client disconnected while receiving JSON
                break

            games[game_id]["last_ping"] = time.time()

            if msg.get("type") == "ping":
                await websocket.send_json({"status": "pong", "id": game_id})

            elif msg.get("type") == "pos":
                x, y = msg.get("x"), msg.get("y")
                users[user]["position"] = (x, y)
                await websocket.send_json({"status": "pos_updated", "x": x, "y": y})

            elif msg.get("type") == "loc":
                target_user = msg.get("user")
                if target_user in users:
                    x, y = users[target_user]["position"]
                    await websocket.send_json({
                        "type": "loc",
                        "user": target_user,
                        "x": x,
                        "y": y
                    })
                else:
                    await websocket.send_json({
                        "type": "loc",
                        "user": target_user,
                        "error": "user not found"
                    })

    except WebSocketDisconnect:
        # This catches any remaining disconnect exceptions
        pass
    finally:
        # Clean up regardless of how we exit
        print(f"WebSocket closed for user {user}")
        if game_id in games:
            del games[game_id]
        if user in users:
            del users[user]
