"""Orion-Net: minimal room server that registers with Orion-Core hub.

This script implements a simple chat room server using the `websockets`
library and also registers itself with the hub (PoW challenge/response).

Environment variables:
- `HUB_URL` (e.g. "wss://localhost:8080") - address of the Orion-Core hub.
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

# Custom Logging
class ColoredFormatter(logging.Formatter):
    BLUE = "\033[38;5;39m"
    GREEN = "\033[38;5;82m"
    YELLOW = "\033[38;5;226m"
    RED = "\033[38;5;196m"
    RESET = "\033[0m"
    GREY = "\033[38;5;240m"

    def format(self, record):
        levelname = record.levelname
        if levelname == "INFO":
            color = self.GREEN
        elif levelname == "WARNING":
            color = self.YELLOW
        elif levelname == "ERROR":
            color = self.RED
        elif levelname == "CRITICAL":
            color = self.RED
        else:
            color = self.GREY
            
        # Format timestamp
        asctime = self.formatTime(record, "%H:%M:%S")
        
        return f"{self.BLUE}{asctime}{self.RESET} {self.GREY}|{self.RESET} {color}{levelname:<8}{self.RESET} {self.GREY}|{self.RESET} {record.getMessage()}"

# Setup Logging
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logging.getLogger().handlers = [handler]
logging.getLogger().setLevel(logging.INFO)

start_time = time.time()

def get_colored_banner():
    raw_banner = """
▛▀▖       ▖      ▐   ▞▀▖   ▗       
▙▄▘▙▀▖▞▀▖▗▖▞▀▖▞▀▖▜▀  ▌ ▌▙▀▖▄ ▞▀▖▛▀▖
▌  ▌  ▌ ▌ ▌▛▀ ▌ ▖▐ ▖ ▌ ▌▌  ▐ ▌ ▌▌ ▌
▘  ▘  ▝▀ ▄▘▝▀▘▝▀  ▀  ▝▀ ▘  ▀▘▝▀ ▘ ▘
"""
    colored_banner = ""
    lines = raw_banner.strip().split('\n')
    
    gradient_colors = [
        "\033[38;5;17m", "\033[38;5;18m", "\033[38;5;19m", "\033[38;5;20m", "\033[38;5;21m",
        "\033[38;5;27m", "\033[38;5;33m", "\033[38;5;39m", "\033[38;5;45m", "\033[38;5;51m",
        "\033[38;5;45m", "\033[38;5;39m", "\033[38;5;33m", "\033[38;5;27m", "\033[38;5;21m"
    ]
    
    for line in lines:
        for i, char in enumerate(line):
            if char == ' ':
                colored_banner += char
            else:
                color_idx = int((i / len(line)) * len(gradient_colors))
                color_idx = min(color_idx, len(gradient_colors) - 1)
                colored_banner += gradient_colors[color_idx] + char
        colored_banner += "\033[0m\n"
        
    return colored_banner

HUB_URL = os.environ.get("HUB_URL", "https://orion-core.onrender.com")
MY_ROOM_NAME = os.environ.get("MY_ROOM_NAME", "Test Room")
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")
PORT = int(os.environ.get("PORT", "8765"))

MAINTENANCE_MODE = False
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
    if MAINTENANCE_MODE:
        await websocket.send("⚠️ Maintenance Mode is ON. Please try again later.")
        await websocket.close()
        return

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
                    motd = os.environ.get('ROOM_MOTD', 'Welcome to this Orion-Net room!')
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
    # Handle auto-discovery from Render (which gives https://)
    hub_url = HUB_URL
    if hub_url.startswith("http://"):
        hub_url = hub_url.replace("http://", "ws://")
    elif hub_url.startswith("https://"):
        hub_url = hub_url.replace("https://", "wss://")
        
    hub_ws_url = hub_url.rstrip("/") + "/ws"
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
                        global MAINTENANCE_MODE
                        MAINTENANCE_MODE = data.get("maintenance", False)
                        if MAINTENANCE_MODE:
                            logging.warning("Hub is in Maintenance Mode")
                        # keep connection alive and listen for broadcasts
                        continue
                    elif data.get("type") == "maintenance_update":
                        MAINTENANCE_MODE = data.get("enabled", False)
                        status = "ON" if MAINTENANCE_MODE else "OFF"
                        logging.warning(f"Maintenance Mode set to {status}")
                        if MAINTENANCE_MODE:
                            await broadcast("[System] ⚠️ Server is entering Maintenance Mode. New connections disabled.")
                        else:
                            await broadcast("[System] ✅ Maintenance Mode disabled.")
                    elif data.get("type") == "broadcast":
                        msg = data.get("message")
                        if msg:
                            logging.info(f"Received system broadcast: {msg}")
                            await broadcast(f"[System] {msg}")
        except Exception as e:
            logging.warning(f"Hub registration failed: {e}")
            await asyncio.sleep(10)


async def main():
    print(get_colored_banner())
    print(f"\033[38;5;39m   :: ORION NET ::   \033[0m v1.0.0\n")
    
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
        print("Orion-Net shutting down")