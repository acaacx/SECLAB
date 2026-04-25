import os
import sys
import time
import json
import random
import datetime
from threading import Thread
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import messagebox
import winsound


def resource_path(filename):
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)


VICTIM_ID = f"SIM-{random.randint(10000, 99999)}"
DURATION = 90

QR_IMAGE = resource_path("QRC.jpg")
ALARM_WAV = resource_path("alert.wav")

EVIDENCE_DIR = os.path.join(os.getcwd(), "sim_evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)


def generate_iocs():
    ts = datetime.datetime.now().isoformat()
    return [
        {"time": ts, "type": "process", "detail": "ransomware.exe (simulated)"},
        {"time": ts, "type": "file", "detail": "Resume.docx.locked"},
        {"time": ts, "type": "file", "detail": "Vacation.jpg.locked"},
        {"time": ts, "type": "network", "detail": "beacon → 10.10.10.10"}
    ]


def save_iocs(iocs):
    path = os.path.join(EVIDENCE_DIR, f"evidence_{int(time.time())}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "victim_id": VICTIM_ID,
            "generated": datetime.datetime.now().isoformat(),
            "iocs": iocs,
            "note": "Simulation only"
        }, f, indent=2)
    return path


def play_alarm():
    if os.path.exists(ALARM_WAV):
        winsound.PlaySound(
            ALARM_WAV,
            winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP
        )


def stop_alarm():
    winsound.PlaySound(None, winsound.SND_PURGE)


def launch_gui():
    root = tk.Tk()
    root.title("Security Alert")
    root.attributes("-fullscreen", True)
    root.attributes("-topmost", True)
    root.overrideredirect(True)
    root.configure(bg="#4b0000")

    play_alarm()

    def keep_focus():
        while True:
            try:
                root.focus_force()
                root.lift()
            except:
                break
            time.sleep(0.4)

    Thread(target=keep_focus, daemon=True).start()

    canvas = tk.Canvas(root, bg="#4b0000", highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    card_w, card_h = 520, 430

    card = tk.Frame(canvas, bg="#e00012")
    canvas.create_window(
        sw // 2,
        sh // 2,
        window=card,
        width=card_w,
        height=card_h
    )

    header = tk.Frame(card, bg="#ff0020", height=150)
    header.pack(fill="x")

    icon = tk.Canvas(header, width=90, height=90, bg="#ff0020", highlightthickness=0)
    icon.pack(pady=18)
    icon.create_polygon(45, 6, 84, 78, 6, 78, fill="white")
    icon.create_text(45, 56, text="!", fill="black", font=("Segoe UI", 32, "bold"))

    tk.Label(
        header,
        text="You've Been Hacked!",
        bg="#ff0020",
        fg="white",
        font=("Segoe UI", 22, "bold")
    ).pack()

    body = tk.Frame(card, bg="#d10014")
    body.pack(fill="both", expand=True, padx=30, pady=20)

    tk.Label(
        body,
        text="Your files have been encrypted.\nScan the QR code below to restore access.",
        bg="#d10014",
        fg="#ffecec",
        font=("Segoe UI", 12),
        justify="center"
    ).pack(pady=(0, 14))

    if os.path.exists(QR_IMAGE):
        img = Image.open(QR_IMAGE).resize((160, 160), Image.LANCZOS)
        qr = ImageTk.PhotoImage(img)
        lbl = tk.Label(body, image=qr, bg="#d10014")
        lbl.image = qr
        lbl.pack()
    else:
        tk.Label(
            body,
            text="QR CODE NOT FOUND",
            fg="white",
            bg="#d10014",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=40)

    status = tk.Label(
        body,
        text="Awaiting payment...",
        bg="#d10014",
        fg="#ffd16a",
        font=("Consolas", 11)
    )
    status.pack(pady=12)

    def ok_action():
        messagebox.showwarning(
            "Payment Required",
            "No payment detected.\nFiles remain encrypted."
        )

    tk.Button(
        body,
        text="OK",
        command=ok_action,
        bg="#ff4a4a",
        fg="black",
        activebackground="#ff6b6b",
        relief="flat",
        font=("Segoe UI", 12, "bold"),
        width=10,
        pady=6
    ).pack(pady=6)

    def countdown():
        start = time.time()
        while time.time() - start < DURATION:
            remaining = int(DURATION - (time.time() - start))
            status.config(text=f"Time remaining: {remaining}s")
            time.sleep(1)

        status.config(text="Deadline expired. Files lost.")
        stop_alarm()

    Thread(target=countdown, daemon=True).start()

    root.mainloop()


if __name__ == "__main__":
    launch_gui()