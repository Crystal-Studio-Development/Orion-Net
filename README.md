# orion-net

Run the room server (development):

```powershell
set HUB_URL=ws://localhost:8080
set MY_ROOM_NAME="My Room"
python orion-net.py
```

Environment variables:
- `HUB_URL` - full base WebSocket URL of the hub (e.g. `ws://localhost:8080`)
- `MY_ROOM_NAME` - friendly name for the room
- `RENDER_EXTERNAL_URL` - optional public URL (used when advertising address to hub)
- `PORT` - listen port for the chat server (default 8765)

The server will try to register with the hub and run a simple chat server for
clients to connect to.