#!/bin/bash

SESSION="securechat"

# Kill existing sessions
tmux kill-session -t $SESSION 2>/dev/null
tmux kill-session -t serverbg 2>/dev/null
tmux kill-session -t chatbg 2>/dev/null

# Start server.py in background
tmux new-session -d -s serverbg "python3 server.py"

# Create main session for Server and Clients
tmux new-session -d -s $SESSION -n clients "python3 chat_server.py"
tmux split-window -d -t $SESSION:0.0 "python3 client.py A"
tmux split-window -h -t $SESSION:0.1 "python3 client.py B"
tmux split-window -h -t $SESSION:0.2 "python3 client.py C"

# Attach to the session
tmux attach-session -t $SESSION
