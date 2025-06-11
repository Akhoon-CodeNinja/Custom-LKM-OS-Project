import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import os
import time

MODULE_NAME = "block_execve.ko"
MODULE_SHORT = "block_execve"
PROC_FILE = "/proc/block_execve"

# -----------------------------
# Utility Functions
# -----------------------------

def is_module_loaded():
    try:
        output = subprocess.check_output(["lsmod"], encoding='utf-8')
        return MODULE_SHORT in output
    except:
        return False

def module_exists():
    return os.path.exists(MODULE_NAME)

def proc_file_exists():
    return os.path.exists(PROC_FILE)

# -----------------------------
# Actions
# -----------------------------

def load_module():
    if is_module_loaded():
        status.set("Module is already loaded.")
        return
    if not module_exists():
        messagebox.showerror("Error", f"Module file '{MODULE_NAME}' not found.")
        return
    try:
        subprocess.run(['pkexec', 'insmod', MODULE_NAME], check=True)
        status.set("Module loaded.")
        time.sleep(0.5)
        refresh_blocklist()
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", "Failed to load module. Are you running with permission?")
        status.set("Failed to load module.")

def unload_module():
    if not is_module_loaded():
        status.set("Module is not loaded.")
        return
    try:
        subprocess.run(['pkexec', 'rmmod', MODULE_SHORT], check=True)
        status.set("Module unloaded.")
        text_area.delete(1.0, tk.END)
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", "Failed to unload module.")
        status.set("Failed to unload module.")

def refresh_blocklist():
    if not proc_file_exists():
        status.set("Proc file not available. Is the module loaded?")
        return
    try:
        with open(PROC_FILE, "r") as f:
            content = f.read()
        text_area.delete(1.0, tk.END)
        text_area.insert(tk.END, content)
        status.set("Blocklist loaded.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read blocklist:\n{e}")
        status.set("Error reading blocklist.")

# -----------------------------
# GUI Setup
# -----------------------------

root = tk.Tk()
root.title("Program Blocker GUI")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Button(frame, text="Load Module", width=15, command=load_module).grid(row=0, column=0, padx=5)
tk.Button(frame, text="Unload Module", width=15, command=unload_module).grid(row=0, column=1, padx=5)
tk.Button(frame, text="Refresh Blocklist", width=20, command=refresh_blocklist).grid(row=0, column=2, padx=5)

text_area = scrolledtext.ScrolledText(root, height=15, width=60)
text_area.pack(padx=10, pady=10)

# Status Bar
status = tk.StringVar()
status.set("Ready.")
status_bar = tk.Label(root, textvariable=status, bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_bar.pack(fill=tk.X)

root.mainloop()
