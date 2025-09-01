# file: gui.py
from tkinter import *
import traceback
from scanner import WebSETScanner

scanner = WebSETScanner()


def start_scan():
    code_input = code_box.get("1.0", END).strip()
    if not code_input:
        dashboard.insert(END, "[ERROR] No code provided.\n")
        return

    dashboard.insert(END, "[INFO] Scan started...\n")

    def on_progress(percent: int, label: str):
        dashboard.insert(END, f"[PROGRESS] {percent}% - {label}\n")
        dashboard.see(END)

    def on_finding(finding: dict):
        dashboard.insert(
            END,
            f"[{finding['severity']}] {finding['title']} "
            f"({finding['path']}): {finding['evidence']}\n"
        )
        dashboard.see(END)

    try:
        for _ in scanner.scan_code(code_input, filename="<pasted>",
                                   on_progress=on_progress,
                                   on_finding=on_finding):
            pass
        dashboard.insert(END, "[INFO] Scan complete.\n")
    except Exception:
        dashboard.insert(END, "[ERROR] Scan failed.\n")
        dashboard.insert(END, traceback.format_exc() + "\n")


def load_report():
    dashboard.insert(END, "[INFO] Report loaded...\n")


def exit_app():
    main.destroy()


# Main window
main = Tk()
main.title("WebSET - Web Security Evaluation Tool")
main.geometry("900x600")
main.config(bg="#b3e5fc")  # baby blue

# Header
header = Label(main, text="WebSET Dashboard", font=("Arial", 18, "bold"),
               fg="black", bg="#b3e5fc")
header.pack(pady=10)

# Frames
left_frame = Frame(main, bg="#81d4fa", width=200, height=500)
left_frame.pack(side=LEFT, fill=Y)

right_frame = Frame(main, bg="#e1f5fe", width=700, height=500)
right_frame.pack(side=RIGHT, fill=BOTH, expand=True)

# Button style fix (black text always visible)
button_style = {
    "width": 20,
    "bg": "#4fc3f7",
    "fg": "black",
    "activebackground": "#29b6f6",
    "activeforeground": "black",
}

btn_scan = Button(left_frame, text="Start Scan", command=start_scan, **button_style)
btn_scan.pack(pady=10)

btn_report = Button(left_frame, text="Load Report", command=load_report, **button_style)
btn_report.pack(pady=10)

btn_exit = Button(left_frame, text="Exit", command=exit_app,
                  bg="#ef5350", fg="black",
                  activebackground="#e53935", activeforeground="black",
                  width=20)
btn_exit.pack(pady=10)

# Code input box
code_label = Label(right_frame, text="Paste Website Code Below:",
                   font=("Arial", 12), bg="#e1f5fe", fg="black")
code_label.pack()

code_box = Text(right_frame, wrap=WORD, font=("Courier", 10), height=10,
                bg="white", fg="black")
code_box.pack(fill=X, padx=10, pady=5)

# === Dashboard with image on the left ===
dashboard_frame = Frame(right_frame, bg="#e1f5fe")
dashboard_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

