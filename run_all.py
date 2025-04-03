
import subprocess
import time
import os

def run_in_new_terminal(command, title):
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", command],
        shell=True
    )

# Give each script time to start
print("[*] Launching secure chat system...")

run_in_new_terminal("python server.py", "Server")
time.sleep(1)

run_in_new_terminal("python chat_server.py", "ChatServer")
time.sleep(1)

run_in_new_terminal("python client.py B", "ClientB")
time.sleep(1)

run_in_new_terminal("python client.py C", "ClientC")
time.sleep(1)

run_in_new_terminal("python client.py A", "ClientA")
print("[*] All terminals launched.")
