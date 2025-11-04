import tkinter as tk
from tkinter import ttk, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import collections
import webbrowser
import os
from Scanner import scan_file
from pdfgen import generate_pdf

root = tk.Tk()
root.title("WebSET Dashboard")
root.geometry("1000x700")
root.configure(bg="#B3E5FC")

# ---------------- Sidebar ----------------
sidebar = tk.Frame(root, bg="white", width=200)
sidebar.pack(side="left", fill="y")

title = tk.Label(sidebar, text="WebSET", font=("Arial", 16, "bold"), bg="skyblue", fg="white", pady=20)
title.pack(fill="x")

# ---------------- Main Area ----------------
main_area = tk.Frame(root, bg="#f4f6f9")
main_area.pack(side="right", expand=True, fill="both")

# ---------------- Top Bar ----------------
topbar = tk.Frame(main_area, bg="#B3E5FC", height=60)
topbar.pack(fill="x")

# ---------------- Table ----------------
table_frame = tk.Frame(main_area, bg="white")
table_frame.pack(fill="both", expand=True, padx=20, pady=10)

columns = ("Threat", "Severity", "Message")
tree = ttk.Treeview(table_frame, columns=columns, show="headings")
tree.heading("Threat", text="Threat")
tree.heading("Severity", text="Severity")
tree.heading("Message", text="Message")
tree.pack(fill="both", expand=True)

# ------------- PDF Directory & Path --------------
home_dir = os.path.expanduser("~")
pdf_dir = f"{home_dir}/WebSET_Reports"
os.makedirs(pdf_dir, exist_ok=True)
pdf_path = f"{pdf_dir}/WebSET_Report.pdf"

# ---------------- Chart ----------------
chart_frame = tk.Frame(main_area, bg="white")
chart_frame.pack(fill="both", expand=True, padx=20, pady=10)

# ---------------- Functions ----------------
def reset_dashboard():
    for item in tree.get_children():
        tree.delete(item)
    for widget in chart_frame.winfo_children():
        widget.destroy()
    print("Dashboard cleared!")

def run_scan():
    file_path = filedialog.askopenfilename(
        filetypes=[("HTML files", "*.html"), ("Java files", "*.java"), ("All files", "*.*")]
    )

    if file_path == "":
        return

    results = scan_file(file_path)
    issues = results["issues"]

    # clear old data
    for item in tree.get_children():
        tree.delete(item)
    for widget in chart_frame.winfo_children():
        widget.destroy()

    # add new data
    for i in issues:
        tree.insert("", "end", values=(i["Threat"], i["Threat Severity"], i["Message"]))

    # count severity
    severities = []
    for i in issues:
        severities.append(i["Threat Severity"])

    counts = collections.Counter(severities)

    # draw chart
    fig, ax = plt.subplots(figsize=(4, 3))
    colors = []
    for s in counts.keys():
        if s == "High":
            colors.append("red")
        elif s == "Medium":
            colors.append("orange")
        else:
            colors.append("green")

    ax.bar(counts.keys(), counts.values(), color=colors)
    ax.set_title("Issues by Severity")

    canvas = FigureCanvasTkAgg(fig, master=chart_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # save chart and pdf
    chart_path = "severity_chart.png"
    fig.savefig(chart_path)
    generate_pdf(results, pdf_path=pdf_path, severity_chart_path=chart_path)

    print("PDF report saved to", pdf_path)


def run_report():
    if os.path.exists(pdf_path):
        webbrowser.open_new(f"file://{pdf_path}")
        print("Opened", pdf_path)
    else:
        print("No report found. Please run a scan first.")

# ---------------- Buttons ----------------
def open_dashboard():
    print("Dashboard button clicked (not used yet).")

def sign_out():
    root.destroy()

# sidebar buttons
btn_dashboard = tk.Label(sidebar, text="Dashboard", bg="white", fg="black", padx=20, pady=10,
                         font=("Arial", 12), anchor="w")
btn_dashboard.pack(fill="x", pady=5, padx=10)

btn_reset = tk.Label(sidebar, text="Reset", bg="white", fg="black", padx=20, pady=10,
                     font=("Arial", 12), anchor="w")
btn_reset.pack(fill="x", pady=5, padx=10)

btn_signout = tk.Label(sidebar, text="Sign Out", bg="white", fg="black", padx=20, pady=10,
                       font=("Arial", 12), anchor="w")
btn_signout.pack(fill="x", pady=5, padx=10)

# hover effects
def hover_enter(e): e.widget.config(bg="#e0f7fa")
def hover_leave(e): e.widget.config(bg="white")

for b in [btn_dashboard, btn_reset, btn_signout]:
    b.bind("<Enter>", hover_enter)
    b.bind("<Leave>", hover_leave)

btn_reset.bind("<Button-1>", lambda e: reset_dashboard())
btn_signout.bind("<Button-1>", lambda e: sign_out())

# topbar buttons
btn_load = tk.Label(topbar, text="Load File & Scan", bg="white", fg="black",
                    padx=20, pady=10, font=("Arial", 12), anchor="center")
btn_load.pack(side="right", padx=5, pady=10)

btn_report = tk.Label(topbar, text="Load Report", bg="white", fg="black",
                      padx=20, pady=10, font=("Arial", 12), anchor="center")
btn_report.pack(side="right", padx=5, pady=10)

btn_load.bind("<Enter>", hover_enter)
btn_load.bind("<Leave>", hover_leave)
btn_report.bind("<Enter>", hover_enter)
btn_report.bind("<Leave>", hover_leave)

btn_load.bind("<Button-1>", lambda e: run_scan())
btn_report.bind("<Button-1>", lambda e: run_report())

root.mainloop()
