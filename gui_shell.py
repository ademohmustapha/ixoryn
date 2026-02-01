import tkinter as tk
import subprocess
import sys

def run_cli():
    subprocess.Popen([sys.executable, "ixoryn.py"])

root = tk.Tk()
root.title("IXORYN Cybersecurity Framework")
root.geometry("400x250")

tk.Label(root, text="IXORYN", font=("Arial", 18)).pack(pady=10)
tk.Label(root, text="Unified Cybersecurity Tool").pack(pady=5)

tk.Button(root, text="Launch IXORYN CLI", width=25, command=run_cli).pack(pady=20)

tk.Label(root, text="Secure by design • Research-grade").pack(side="bottom", pady=10)

root.mainloop()

