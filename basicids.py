import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from datetime import datetime
import threading

# ---------------- Config ---------------- #
PORT_SCAN_THRESHOLD = 10    # Ports touched before we call "port scan"
SYN_FLOOD_THRESHOLD = 50    # SYN packets before we warn
ALERTS_LOG_FILE = "alerts.log"

# ---------------- State ---------------- #
connection_attempts = {}    # {src_ip: {"ports": set(), "syn_count": int}}
sniffer = None              # AsyncSniffer instance
ids_running = False         # state flag


# ---------------- IDS Logic ---------------- #
def detect_attack(pkt):
    """Called for every packet captured by sniffer."""
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto_name = "OTHER"

    # Track TCP info for detection rules
    if pkt.haslayer(TCP):
        proto_name = "TCP"
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags

        if src_ip not in connection_attempts:
            connection_attempts[src_ip] = {"ports": set(), "syn_count": 0}

        connection_attempts[src_ip]["ports"].add(dst_port)

        # SYN check
        if flags == "S":
            connection_attempts[src_ip]["syn_count"] += 1

        # Port Scan detection
        if len(connection_attempts[src_ip]["ports"]) > PORT_SCAN_THRESHOLD:
            log_alert(
                f"Potential Port Scan from {src_ip} "
                f"(unique ports: {len(connection_attempts[src_ip]['ports'])})",
                proto_name
            )

        # SYN Flood detection
        if connection_attempts[src_ip]["syn_count"] > SYN_FLOOD_THRESHOLD:
            log_alert(
                f"Potential SYN Flood from {src_ip} "
                f"(SYN count: {connection_attempts[src_ip]['syn_count']})",
                proto_name
            )

    elif pkt.haslayer(UDP):
        proto_name = "UDP"
    elif pkt.haslayer(ICMP):
        proto_name = "ICMP"

    # Log all observed traffic (comment out if too noisy)
    log_alert(f"{src_ip} -> {dst_ip}", proto_name)


# ---------------- Logging ---------------- #
def log_alert(message, proto):
    ts = datetime.now().strftime("%H:%M:%S")
    # Insert into GUI table (thread-safe via after)
    root.after(0, lambda: tree.insert("", "end", values=(ts, proto, message)))
    # Append to file
    with open(ALERTS_LOG_FILE, "a") as f:
        f.write(f"{ts} [{proto}] {message}\n")


# ---------------- Control ---------------- #
def start_ids():
    global sniffer, ids_running
    if ids_running:
        return
    ids_running = True
    status_var.set("Running...")
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    clear_button.config(state=tk.DISABLED)  # disable clear while running

    # Start AsyncSniffer in background thread
    sniffer = AsyncSniffer(prn=detect_attack, store=False)
    sniffer.start()


def stop_ids():
    global sniffer, ids_running
    if not ids_running:
        return
    ids_running = False
    try:
        sniffer.stop()
    except Exception as e:
        messagebox.showerror("Stop Error", str(e))
    status_var.set("Stopped.")
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    clear_button.config(state=tk.NORMAL)


def clear_logs():
    """Clear GUI table, reset state, truncate alerts.log."""
    # Clear table
    for item in tree.get_children():
        tree.delete(item)
    # Reset detection state
    connection_attempts.clear()
    # Truncate log file
    open(ALERTS_LOG_FILE, "w").close()
    status_var.set("Logs cleared.")


# ---------------- GUI ---------------- #
root = tk.Tk()
root.title("Basic IDS - Live Network Monitor")
root.geometry("950x540")
root.configure(bg="#0b1225")  # Dark blue

# Style
style = ttk.Style()
style.theme_use("clam")
style.configure(
    "Treeview",
    background="#0b1225",
    foreground="white",
    fieldbackground="#0b1225",
    font=("Consolas", 10),
    rowheight=24
)
style.configure(
    "Treeview.Heading",
    font=("Consolas", 11, "bold"),
    foreground="#00d4ff",
    background="#1c2b4a"
)
style.map("Treeview", background=[("selected", "#1f3b6d")])

# Title
title_label = tk.Label(
    root,
    text="🔍 Basic Intrusion Detection System (IDS)",
    font=("Consolas", 16, "bold"),
    fg="#00d4ff",
    bg="#0b1225",
)
title_label.pack(pady=10)

# Table
columns = ("Time", "Protocol", "Alert Message")
tree = ttk.Treeview(root, columns=columns, show="headings", height=14)
tree.heading("Time", text="Time")
tree.heading("Protocol", text="Protocol")
tree.heading("Alert Message", text="Alert Message")
tree.column("Time", width=100, anchor="center")
tree.column("Protocol", width=100, anchor="center")
tree.column("Alert Message", width=700, anchor="w")
tree.pack(fill="both", expand=True, pady=10, padx=10)

# Buttons frame
btn_frame = tk.Frame(root, bg="#0b1225")
btn_frame.pack(pady=10)

start_button = tk.Button(
    btn_frame,
    text="Start IDS",
    font=("Consolas", 12, "bold"),
    bg="#1f3b6d",
    fg="white",
    relief="flat",
    padx=12,
    pady=5,
    command=start_ids
)
start_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(
    btn_frame,
    text="Stop IDS",
    font=("Consolas", 12, "bold"),
    bg="#5b1f1f",
    fg="white",
    relief="flat",
    padx=12,
    pady=5,
    state=tk.DISABLED,
    command=stop_ids
)
stop_button.grid(row=0, column=1, padx=5)

clear_button = tk.Button(
    btn_frame,
    text="Clear Logs",
    font=("Consolas", 12, "bold"),
    bg="#1c2b4a",
    fg="white",
    relief="flat",
    padx=12,
    pady=5,
    command=clear_logs
)
clear_button.grid(row=0, column=2, padx=5)

# Status label
status_var = tk.StringVar(value="Idle.")
status_label = tk.Label(
    root,
    textvariable=status_var,
    font=("Consolas", 11),
    fg="white",
    bg="#0b1225"
)
status_label.pack(pady=5)

root.mainloop()
