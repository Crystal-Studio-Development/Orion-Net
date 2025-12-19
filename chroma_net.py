"""Chroma-Net: minimal room server that registers with Chroma-Core hub.

This script implements a simple chat room server using the `websockets`
library and also registers itself with the hub (PoW challenge/response).

Environment variables:
- `HUB_URL` (e.g. "wss://localhost:8080") - address of the Chroma-Core hub.
- `MY_ROOM_NAME` - friendly name of this room.
- `RENDER_EXTERNAL_URL` - public URL (used to compute public WSS address). If
  not provided, the server will report a best-effort address based on host:port.
- `PORT` - port to listen on (default 8765).
"""

import asyncio
import os
import json
import logging
import hashlib
import time
from websockets import serve, connect

logging.basicConfig(level=logging.INFO)
start_time = time.time()

HUB_URL = os.environ.get("HUB_URL", "ws://localhost:8080")
MY_ROOM_NAME = os.environ.get("MY_ROOM_NAME", "Test Room")
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")
PORT = int(os.environ.get("PORT", "8765"))

connected_clients = set()
client_names = {}


async def broadcast(message):
    if not connected_clients:
        return
    # Create a copy to avoid "Set changed size during iteration" error
    clients_copy = list(connected_clients)
    to_remove = []
    for ws in clients_copy:
        try:
            await ws.send(message)
        except Exception:
            to_remove.append(ws)
    for ws in to_remove:
        connected_clients.discard(ws)


async def handle_chat_client(websocket):
    client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    logging.info(f"New client connected from {client_ip}")
    connected_clients.add(websocket)
    try:
        await websocket.send("Welcome! Please enter your name:")
        name = await websocket.recv()
        client_names[websocket] = name
        logging.info(f"Client '{name}' joined the room (total: {len(connected_clients)})")
        await broadcast(f"--- {name} has joined the room ---")
        
        # Send help message
        await websocket.send("Commands: /help, /who, /time, /uptime, /motd")
        
        async for message in websocket:
            sender = client_names.get(websocket, "anonymous")
            
            # Handle commands
            if message.startswith('/'):
                cmd = message.lower().strip()
                
                if cmd == '/help':
                    help_text = "Available commands:\n/help - Show this help\n/who - List users\n/time - Current time\n/uptime - Room uptime\n/motd - Message of the day\n/nick <name> - Change nickname"
                    await websocket.send(help_text)
                    
                elif cmd == '/who':
                    users = [client_names.get(ws, 'anonymous') for ws in connected_clients]
                    await websocket.send(f"Users in room ({len(users)}): {', '.join(users)}")
                    
                elif cmd == '/time':
                    import datetime
                    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    await websocket.send(f"Current time: {now}")
                    
                elif cmd == '/uptime':
                    import time
                    uptime = time.time() - start_time
                    hours, remainder = divmod(int(uptime), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    await websocket.send(f"Room uptime: {hours}h {minutes}m {seconds}s")
                    
                elif cmd == '/motd':
                    motd = os.environ.get('ROOM_MOTD', 'Welcome to this Chroma-Net room!')
                    await websocket.send(f"MOTD: {motd}")
                    
                elif cmd.startswith('/nick '):
                    new_name = cmd[6:].strip()
                    if new_name and len(new_name) <= 20:
                        old_name = client_names[websocket]
                        client_names[websocket] = new_name
                        await broadcast(f"--- {old_name} changed name to {new_name} ---")
                        logging.info(f"Client '{old_name}' changed name to '{new_name}'")
                    else:
                        await websocket.send("Invalid nickname (max 20 characters)")
                        
                else:
                    await websocket.send(f"Unknown command: {cmd}. Type /help for available commands.")
            else:
                # Regular chat message
                logging.info(f"[{sender}]: {message}")
                await broadcast(f"[{sender}] {message}")
                
    except Exception as e:
        logging.warning(f"Client connection error: {e}")
    finally:
        connected_clients.discard(websocket)
        name = client_names.pop(websocket, "anonymous")
        logging.info(f"Client '{name}' left the room (remaining: {len(connected_clients)})")
        await broadcast(f"--- {name} has left the room ---")


def solve_challenge(challenge_string, difficulty):
    # brute-force integer nonce until hash starts with required zeros
    target = "0" * difficulty
    nonce = 0
    while True:
        s = f"{challenge_string}{nonce}".encode()
        digest = hashlib.sha256(s).hexdigest()
        if digest.startswith(target):
            return str(nonce)
        nonce += 1


async def register_with_hub():
    hub_ws_url = HUB_URL.rstrip("/") + "/ws"
    while True:
        try:
            logging.info(f"Connecting to hub {hub_ws_url} for registration")
            async with connect(hub_ws_url) as ws:
                # prepare public address
                if RENDER_EXTERNAL_URL:
                    my_address = RENDER_EXTERNAL_URL.replace("https://", "wss://").replace("http://", "ws://")
                else:
                    my_address = f"ws://localhost:{PORT}"
                reg = {"type": "register", "name": MY_ROOM_NAME, "address": my_address}
                await ws.send(json.dumps(reg))
                async for raw in ws:
                    try:
                        data = json.loads(raw)
                    except Exception:
                        continue
                    if data.get("type") == "challenge":
                        challenge = data.get("challenge_string")
                        difficulty = int(data.get("difficulty", 4))
                        logging.info("Solving PoW challenge...")
                        nonce = solve_challenge(challenge, difficulty)
                        await ws.send(json.dumps({"type": "response", "challenge_string": challenge, "nonce": nonce}))
                    elif data.get("type") == "success":
                        logging.info("Registered with hub successfully")
                        # keep connection alive until closed
                        await ws.wait_closed()
                        break
        except Exception as e:
            logging.warning(f"Hub registration failed: {e}")
            await asyncio.sleep(10)


async def main():
    # start chat server and hub registration concurrently
    chat_server = serve(handle_chat_client, "0.0.0.0", PORT)
    logging.info(f"Starting chat server on port {PORT}")
    async with chat_server:
        reg_task = asyncio.create_task(register_with_hub())
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Chroma-Net shutting down")