import os, time, hashlib, shutil, threading, csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

BASE_DIR = os.path.abspath(".")
LOG_DIR = "logs"
BACKUP_DIR = "backups"
HASH_DB = os.path.join(LOG_DIR, "fim_hashes.txt")
ALERT_LOG = os.path.join(LOG_DIR, "fim_alerts.txt")
DEMO_FILE = os.path.join(BASE_DIR, "demo_file.txt")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None


def backup_name(path):
    return os.path.join(BACKUP_DIR, os.path.relpath(path, BASE_DIR).replace(os.sep, "_"))


def backup_file(path):
    try:
        shutil.copy2(path, backup_name(path))
    except:
        pass


def restore_file(path):
    src = backup_name(path)

    if not os.path.exists(src):
        return "No backup available."

    try:
        shutil.copy2(src, path)
        return "File restored successfully."
    except:
        return "Restore failed."


def load_hashes():
    if not os.path.exists(HASH_DB):
        return {}

    data = {}
    with open(HASH_DB, "r", encoding="utf-8") as f:
        for line in f:
            try:
                path, h = line.strip().split(" || ")
                data[path] = h
            except:
                pass
    return data


def save_hashes(data):
    with open(HASH_DB, "w", encoding="utf-8") as f:
        for path, h in data.items():
            f.write(f"{path} || {h}\n")


def write_log(event, path):
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{now()}] {event}: {path}\n")


class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FIM - File Integrity Monitor")
        self.root.geometry("1180x700")
        self.root.configure(bg="#0f172a")

        self.running = False
        self.last_state = {}
        self.selected_folder = tk.StringVar(value=BASE_DIR)

        self.vars = {
            "status": tk.StringVar(value="Stopped"),
            "files": tk.StringVar(value="0"),
            "added": tk.StringVar(value="0"),
            "modified": tk.StringVar(value="0"),
            "deleted": tk.StringVar(value="0"),
            "total": tk.StringVar(value="0"),
            "filter": tk.StringVar(value="All Changes")
        }

        self.setup_style()
        self.build_ui()

    def setup_style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background="#111827", foreground="#e5e7eb", fieldbackground="#111827", rowheight=30)
        s.configure("Treeview.Heading", background="#1f2937", foreground="white", font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", "#2563eb")])

    def build_ui(self):
        side = tk.Frame(self.root, bg="#020617", width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        main = tk.Frame(self.root, bg="#0f172a")
        main.pack(side="right", fill="both", expand=True)

        tk.Label(side, text="🛡  FIM", bg="#020617", fg="white", font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=20, pady=(25, 2))
        tk.Label(side, text="File Integrity Monitor", bg="#020617", fg="#94a3b8").pack(anchor="w", padx=23, pady=(0, 25))

        for item in ["Dashboard", "Baseline Scan", "Detected Changes", "Logs"]:
            active = item == "Dashboard"
            tk.Label(side, text=f"   {item}", bg="#1d4ed8" if active else "#020617",
                     fg="white" if active else "#cbd5e1", anchor="w", pady=11).pack(fill="x", padx=12, pady=2)

        box = tk.Frame(side, bg="#052e16", highlightbackground="#14532d", highlightthickness=1)
        box.pack(side="bottom", fill="x", padx=14, pady=16)
        tk.Label(box, textvariable=self.vars["status"], bg="#052e16", fg="#22c55e", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 3))
        tk.Label(box, text="Real-time file monitoring", bg="#052e16", fg="#bbf7d0", font=("Segoe UI", 8)).pack(anchor="w", padx=14, pady=(0, 12))

        header = tk.Frame(main, bg="#0f172a")
        header.pack(fill="x", padx=22, pady=(20, 10))

        title = tk.Frame(header, bg="#0f172a")
        title.pack(side="left")
        tk.Label(title, text="File Integrity Dashboard", bg="#0f172a", fg="white", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(title, text="Detects added, modified, and deleted files using SHA-256 hashes.", bg="#0f172a", fg="#94a3b8").pack(anchor="w")

        buttons = tk.Frame(header, bg="#0f172a")
        buttons.pack(side="right")
        self.btn(buttons, "Create Baseline", self.create_baseline, "#1d4ed8").pack(side="left", padx=5)
        self.btn(buttons, "▶ Start", self.start, "#166534").pack(side="left", padx=5)
        self.btn(buttons, "■ Stop", self.stop, "#991b1b").pack(side="left", padx=5)
        self.btn(buttons, "Export Logs", self.export_logs, "#334155").pack(side="left", padx=5)

        folder = tk.Frame(main, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        folder.pack(fill="x", padx=22, pady=(0, 10))

        tk.Label(folder, text="Monitored Folder:", bg="#111827", fg="#94a3b8").pack(side="left", padx=12)
        tk.Entry(folder, textvariable=self.selected_folder, bg="#020617", fg="white", relief="flat", width=80).pack(side="left", padx=8, pady=10, ipady=5)
        self.btn(folder, "Browse", self.choose_folder, "#334155").pack(side="left", padx=5)

        cards = tk.Frame(main, bg="#0f172a")
        cards.pack(fill="x", padx=22, pady=10)

        for label, key, color in [
            ("Baseline Files", "files", "#38bdf8"),
            ("Added", "added", "#22c55e"),
            ("Modified", "modified", "#facc15"),
            ("Deleted", "deleted", "#f87171"),
            ("Total Changes", "total", "#c084fc")
        ]:
            self.card(cards, label, self.vars[key], color).pack(side="left", fill="x", expand=True, padx=5)

        panel = tk.Frame(main, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        panel.pack(fill="both", expand=True, padx=22, pady=(8, 10))

        top = tk.Frame(panel, bg="#111827")
        top.pack(fill="x", padx=14, pady=(12, 8))

        tk.Label(top, text="DETECTED FILE CHANGES", bg="#111827", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Combobox(top, textvariable=self.vars["filter"], values=["All Changes", "Added", "Modified", "Deleted", "Restored"],
                     state="readonly", width=18).pack(side="right")

        cols = ("time", "event", "file", "hash")
        self.table = ttk.Treeview(panel, columns=cols, show="headings", height=17)

        for col, head in zip(cols, ("Time", "Event", "File Path", "SHA-256 Hash")):
            self.table.heading(col, text=head)
            self.table.column(col, width=130, anchor="center")

        self.table.column("file", width=470, anchor="w")
        self.table.column("hash", width=300, anchor="w")

        for tag, color in [("Added", "#22c55e"), ("Modified", "#facc15"), ("Deleted", "#f87171"), ("Restored", "#38bdf8")]:
            self.table.tag_configure(tag, foreground=color)

        self.table.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        bottom = tk.Frame(main, bg="#0f172a")
        bottom.pack(fill="x", padx=22, pady=(0, 14))

        self.btn(bottom, "Create Test File", self.demo_create, "#166534").pack(side="left", padx=4)
        self.btn(bottom, "Modify Test File", self.demo_modify, "#92400e").pack(side="left", padx=4)
        self.btn(bottom, "Delete Test File", self.demo_delete, "#991b1b").pack(side="left", padx=4)
        self.btn(bottom, "View Logs", self.view_logs, "#334155").pack(side="left", padx=4)
        self.btn(bottom, "Clear Table", self.clear_table, "#334155").pack(side="left", padx=4)
        self.btn(bottom, "Restore Selected", self.restore_selected, "#1d4ed8").pack(side="left", padx=4)

    def btn(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd, bg=color, fg="white", relief="flat",
                         padx=14, pady=8, font=("Segoe UI", 9, "bold"), cursor="hand2")

    def card(self, parent, title, var, color):
        box = tk.Frame(parent, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        tk.Label(box, text=title, bg="#111827", fg="#94a3b8").pack(anchor="w", padx=15, pady=(13, 3))
        tk.Label(box, textvariable=var, bg="#111827", fg=color, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=15, pady=(0, 12))
        return box

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder.set(folder)

    def scan_files(self):
        folder = self.selected_folder.get()
        data = {}

        for rootdir, _, files in os.walk(folder):
            if LOG_DIR in rootdir or BACKUP_DIR in rootdir:
                continue

            for name in files:
                path = os.path.join(rootdir, name)
                h = get_hash(path)
                if h:
                    data[path] = h

        return data

    def create_baseline(self):
        self.last_state = self.scan_files()
        save_hashes(self.last_state)

        for path in self.last_state:
            backup_file(path)

        self.vars["files"].set(str(len(self.last_state)))
        messagebox.showinfo("FIM", f"Baseline created.\nFiles recorded: {len(self.last_state)}")

    def start(self):
        if self.running:
            return messagebox.showinfo("FIM", "Monitoring is already running.")

        if not self.last_state:
            self.last_state = load_hashes() or self.scan_files()
            save_hashes(self.last_state)

        self.running = True
        self.vars["status"].set("Monitoring")
        threading.Thread(target=self.monitor, daemon=True).start()

    def stop(self):
        self.running = False
        self.vars["status"].set("Stopped")

    def monitor(self):
        while self.running:
            new_state = self.scan_files()

            for path in self.last_state:
                if path not in new_state:
                    self.report("Deleted", path, "N/A")

            for path, h in new_state.items():
                if path not in self.last_state:
                    backup_file(path)
                    self.report("Added", path, h)
                elif self.last_state[path] != h:
                    backup_file(path)
                    self.report("Modified", path, h)

            self.last_state = dict(new_state)
            save_hashes(new_state)
            self.root.after(0, lambda: self.vars["files"].set(str(len(new_state))))
            time.sleep(1)

    def report(self, event, path, h):
        short_hash = h[:32] + "..." if h != "N/A" else "N/A"
        write_log(event, path)
        self.root.after(0, self.add_row, (now(), event, path, short_hash), event)

    def add_row(self, row, event):
        mode = self.vars["filter"].get()
        if mode != "All Changes" and mode != event:
            return

        self.table.insert("", 0, values=row, tags=(event,))
        self.vars["total"].set(str(int(self.vars["total"].get()) + 1))

        if event == "Added":
            self.vars["added"].set(str(int(self.vars["added"].get()) + 1))
        elif event == "Modified":
            self.vars["modified"].set(str(int(self.vars["modified"].get()) + 1))
        elif event == "Deleted":
            self.vars["deleted"].set(str(int(self.vars["deleted"].get()) + 1))

    def demo_create(self):
        with open(DEMO_FILE, "w", encoding="utf-8") as f:
            f.write(f"Demo file created at {now()}\n")

    def demo_modify(self):
        with open(DEMO_FILE, "a", encoding="utf-8") as f:
            f.write(f"Modified at {now()}\n")

    def demo_delete(self):
        if os.path.exists(DEMO_FILE):
            os.remove(DEMO_FILE)
        else:
            messagebox.showinfo("FIM", "Demo file does not exist yet. Click Create Test File first.")

    def clear_table(self):
        self.table.delete(*self.table.get_children())
        for key in ["added", "modified", "deleted", "total"]:
            self.vars[key].set("0")

    def view_logs(self):
        win = tk.Toplevel(self.root)
        win.title("FIM Logs")
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, height=30, width=120, font=("Consolas", 10))
        txt.pack()

        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG, "r", encoding="utf-8") as f:
                txt.insert(tk.END, f.read() or "No logs yet.")
        else:
            txt.insert(tk.END, "No logs yet.")

    def export_logs(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV File", "*.csv")])
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Event", "File Path", "SHA-256 Hash"])
            for item in self.table.get_children():
                writer.writerow(self.table.item(item)["values"])

        messagebox.showinfo("FIM", "Logs exported successfully.")

    def restore_selected(self):
        item = self.table.selection()
        if not item:
            return messagebox.showinfo("FIM", "Select a file row first.")

        file_path = self.table.item(item[0])["values"][2]
        result = restore_file(file_path)
        messagebox.showinfo("Restore File", result)

        if result.startswith("File restored"):
            self.report("Restored", file_path, get_hash(file_path) or "N/A")

    def close(self):
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = FIMApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()