# Toy MCP stdio server for the HTTP tool class (T4): the http_tool_call
# actions as MCP tools of the harness (pi spawns it from the harness MCP
# config; see server.py). Build context = ../targets.
# Baked into the pi harness image (harnesses/pi/Dockerfile) — no compose
# service of its own; its child processes run inside the harness container.
