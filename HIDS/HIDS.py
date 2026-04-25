
import os, csv, time, threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil

LOG_DIR = "../logs"
LOG_FILE = os.path.join(LOG_DIR, "hids_alerts.log")
KEYWORDS = ["keylog", "keylogger", "password_stealer", "credential_dump", "reverse_shell", "backdoor", "payload", "malware"]
TRUSTED = {"system idle process", "system", "registry", "svchost.exe", "runtimebroker.exe", "searchhost.exe",
        "taskhostw.exe", "explorer.exe", "chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe",
        "code.exe", "powershell.exe", "cmd.exe", "conhost.exe", "armourycrate.usersessionhelper.exe"}


class HIDSApp:
    def __init__(self, root):
        self.root, self.running, self.detected = root, False, set()
        self.root.title("HIDS - Host Intrusion Detection System")
        self.root.geometry("1180x700")
        self.root.configure(bg="#0f172a")
        os.makedirs(LOG_DIR, exist_ok=True)

        self.vars = {k: tk.StringVar(value=v) for k, v in {
            "total": "0", "sus": "0", "alerts": "0", "cpu": "0%", "mem": "0%", "status": "Stopped", "filter": "All Processes"
        }.items()}

        self.style()
        self.ui()

    def style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background="#111827", foreground="#e5e7eb", fieldbackground="#111827", rowheight=28)
        s.configure("Treeview.Heading", background="#1f2937", foreground="#f8fafc", font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", "#2563eb")])

    def ui(self):
        side = tk.Frame(self.root, bg="#020617", width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        main = tk.Frame(self.root, bg="#0f172a")
        main.pack(side="right", fill="both", expand=True)

        tk.Label(side, text="🛡  HIDS", bg="#020617", fg="white", font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=20, pady=(25, 2))
        tk.Label(side, text="Host Intrusion Detection", bg="#020617", fg="#94a3b8").pack(anchor="w", padx=23, pady=(0, 25))

        for item in ["Dashboard", "Live Processes", "Alerts", "Logs"]:
            active = item == "Dashboard"
            tk.Label(side, text=f"   {item}", bg="#1d4ed8" if active else "#020617",
                    fg="white" if active else "#cbd5e1", anchor="w", pady=11).pack(fill="x", padx=12, pady=2)

        box = tk.Frame(side, bg="#052e16", highlightbackground="#14532d", highlightthickness=1)
        box.pack(side="bottom", fill="x", padx=14, pady=16)
        tk.Label(box, textvariable=self.vars["status"], bg="#052e16", fg="#22c55e", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 3))
        tk.Label(box, text="System monitoring status", bg="#052e16", fg="#bbf7d0", font=("Segoe UI", 8)).pack(anchor="w", padx=14, pady=(0, 12))

        header = tk.Frame(main, bg="#0f172a")
        header.pack(fill="x", padx=22, pady=(20, 10))
        tk.Label(header, text="Host-Based IDS Dashboard", bg="#0f172a", fg="white", font=("Segoe UI", 22, "bold")).pack(side="left")

        buttons = tk.Frame(header, bg="#0f172a")
        buttons.pack(side="right")
        self.button(buttons, "▶ Start", self.start, "#166534").pack(side="left", padx=5)
        self.button(buttons, "■ Stop", self.stop, "#991b1b").pack(side="left", padx=5)
        self.button(buttons, "Export Logs", self.export_logs, "#334155").pack(side="left", padx=5)

        cards = tk.Frame(main, bg="#0f172a")
        cards.pack(fill="x", padx=22, pady=10)

        for title, key, color in [
            ("Total Processes", "total", "#38bdf8"),
            ("Suspicious", "sus", "#f87171"),
            ("Alerts", "alerts", "#facc15"),
            ("CPU Usage", "cpu", "#22c55e"),
            ("Memory Usage", "mem", "#c084fc")
        ]:
            self.card(cards, title, self.vars[key], color).pack(side="left", fill="x", expand=True, padx=5)

        self.proc_table = self.table_panel(
            main, "LIVE PROCESS MONITOR",
            ("time", "name", "pid", "user", "cpu", "mem", "status", "rep"),
            ("Time", "Process Name", "PID", "User", "CPU %", "Memory MB", "Status", "Reputation"),
            height=10,
            with_filter=True
        )

        self.alert_table = self.table_panel(
            main, "RECENT ALERTS",
            ("time", "type", "process", "pid", "details"),
            ("Time", "Alert Type", "Process", "PID", "Details"),
            height=6
        )

        for tag, color in [("trusted", "#22c55e"), ("normal", "#e5e7eb"), ("suspicious", "#f87171"), ("alert", "#f87171")]:
            self.proc_table.tag_configure(tag, foreground=color)
            self.alert_table.tag_configure(tag, foreground=color)

    def button(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd, bg=color, fg="white", relief="flat",
                        padx=14, pady=8, font=("Segoe UI", 9, "bold"), cursor="hand2")

    def card(self, parent, title, var, color):
        f = tk.Frame(parent, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        tk.Label(f, text=title, bg="#111827", fg="#94a3b8").pack(anchor="w", padx=15, pady=(13, 3))
        tk.Label(f, textvariable=var, bg="#111827", fg=color, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=15, pady=(0, 12))
        return f

    def table_panel(self, parent, title, cols, heads, height=8, with_filter=False):
        p = tk.Frame(parent, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        p.pack(fill="both", expand=True, padx=22, pady=(8, 10))

        top = tk.Frame(p, bg="#111827")
        top.pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(top, text=title, bg="#111827", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left")

        if with_filter:
            ttk.Combobox(top, textvariable=self.vars["filter"], values=["All Processes", "Suspicious Only", "Trusted Only"],
                        state="readonly", width=18).pack(side="right")

        t = ttk.Treeview(p, columns=cols, show="headings", height=height)
        for c, h in zip(cols, heads):
            t.heading(c, text=h)
            t.column(c, width=120, anchor="center")

        if "name" in cols: t.column("name", width=220)
        if "details" in cols: t.column("details", width=450)

        t.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        return t

    def start(self):
        if self.running:
            return messagebox.showinfo("HIDS", "Monitoring is already running.")
        self.running = True
        self.vars["status"].set("Monitoring")
        threading.Thread(target=self.monitor, daemon=True).start()
        self.add_alert("System Started", "HIDS", "N/A", "Monitoring started.")

    def stop(self):
        self.running = False
        self.vars["status"].set("Stopped")
        self.add_alert("System Stopped", "HIDS", "N/A", "Monitoring stopped.")

    def monitor(self):
        while self.running:
            rows, suspicious = [], 0
            cpu_total = psutil.cpu_percent(interval=0.2)
            mem_total = psutil.virtual_memory().percent

            for p in psutil.process_iter(["pid", "name", "username", "cmdline", "memory_info", "status"]):
                try:
                    i = p.info
                    name = i.get("name") or "unknown"
                    pid = i.get("pid")
                    user = str(i.get("username") or "N/A").split("\\")[-1]
                    cmd = " ".join(i.get("cmdline") or [])
                    mem = round((i["memory_info"].rss / 1048576), 2) if i.get("memory_info") else 0
                    cpu = round(p.cpu_percent(interval=0.0), 1)
                    rep, reason = self.check(name, cmd, cpu, mem)

                    if rep == "Suspicious":
                        suspicious += 1
                        self.add_alert_once("Suspicious Process Detected", name, pid, reason)

                    rows.append((datetime.now().strftime("%H:%M:%S"), name, pid, user, cpu, mem, i.get("status") or "running", rep))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            self.root.after(0, self.refresh, rows, suspicious, cpu_total, mem_total)
            time.sleep(2)

    def check(self, name, cmd, cpu, mem):
        n, text = name.lower(), f"{name} {cmd}".lower()
        if n in TRUSTED:
            return "Trusted", "Trusted process"
        for word in KEYWORDS:
            if word in text:
                return "Suspicious", f"Matched suspicious pattern: {word}"
        if cpu >= 80:
            return "Suspicious", f"Unusual CPU usage: {cpu}%"
        if mem >= 800:
            return "Suspicious", f"Unusual memory usage: {mem} MB"
        return "Normal", "No suspicious behavior"

    def refresh(self, rows, suspicious, cpu, mem):
        self.proc_table.delete(*self.proc_table.get_children())
        mode = self.vars["filter"].get()

        for r in rows[:120]:
            rep = r[-1]
            if mode == "Suspicious Only" and rep != "Suspicious": continue
            if mode == "Trusted Only" and rep != "Trusted": continue
            self.proc_table.insert("", "end", values=r, tags=(rep.lower(),))

        self.vars["total"].set(str(len(rows)))
        self.vars["sus"].set(str(suspicious))
        self.vars["cpu"].set(f"{cpu}%")
        self.vars["mem"].set(f"{mem}%")

    def add_alert_once(self, alert_type, process, pid, details):
        key = f"{process}-{pid}-{details}"
        if key not in self.detected:
            self.detected.add(key)
            self.add_alert(alert_type, process, pid, details)

    def add_alert(self, alert_type, process, pid, details):
        ts = datetime.now().strftime("%H:%M:%S")
        row = (ts, alert_type, process, pid, details)
        self.alert_table.insert("", 0, values=row, tags=("alert",))
        self.vars["alerts"].set(str(int(self.vars["alerts"].get()) + 1))
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {alert_type} | {process} | PID={pid} | {details}\n")

    def export_logs(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV File", "*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Time", "Alert Type", "Process", "PID", "Details"])
            for item in self.alert_table.get_children():
                w.writerow(self.alert_table.item(item)["values"])
        messagebox.showinfo("HIDS", "Logs exported successfully.")

    def close(self):
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = HIDSApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()
    