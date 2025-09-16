import tkinter as tk
from tkinter import ttk, filedialog
from scanner import scan_file
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import collections

root = tk.Tk()
root.title("WebSET Dashboard")
root.geometry("1000x700")
root.configure(bg="#B3E5FC")

# buttons on the side
sidebar = tk.Frame(root, bg="white", width=200)
sidebar.pack(side="left", fill="y")

title = tk.Label(
    sidebar,
    text="WebSET",
    font=("Arial", 16, "bold"),
    bg="sky blue",
    fg="white",
    pady=20
)
title.pack(fill="x")

def create_modern_button(parent, text):
    btn = tk.Label(
        parent,
        text=text,
        bg="white",
        fg="black",
        padx=20,
        pady=10,
        font=("Arial", 12),
        anchor="w",
        relief="flat",
        bd=0
    )
    btn.pack(fill="x", pady=5, padx=10)

    # Hover effect
    def on_enter(e):
        btn.config(bg="#e0f7fa")
    def on_leave(e):
        btn.config(bg="white")

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

    return btn

# Create all sidebar buttons
buttons = ["Dashboard", "Cases", "Create Case", "Search Code", "Sign Out"]
for b_text in buttons:
    btn = create_modern_button(sidebar, b_text)
    if b_text == "Sign Out":
        # exit the ui
        btn.bind("<Button-1>", lambda e: root.destroy())


# Main section for dash
main_area = tk.Frame(root, bg="#f4f6f9")
main_area.pack(side="right", expand=True, fill="both")

# Top Bar
topbar = tk.Frame(main_area, bg="#B3E5FC", height=60)
topbar.pack(fill="x")

# top bar button should be the same style
btn_load = tk.Label(
    topbar,
    text="Load File & Scan",
    bg="white",
    fg="black",
    padx=20,
    pady=10,
    font=("Arial", 12),
    anchor="w",
    relief="flat",
    bd=0
)
btn_load.pack(side="right", padx=5, pady=10)

# Hover effect
def on_enter(e):
    btn_load.config(bg="#e0f7fa")

def on_leave(e):
    btn_load.config(bg="white")

btn_load.bind("<Enter>", on_enter)
btn_load.bind("<Leave>", on_leave)

# Click to run scan
btn_load.bind("<Button-1>", lambda e: run_scan())



# Table for vulnerabilities
table_frame = tk.Frame(main_area, bg="white")
table_frame.pack(fill="both", expand=True, padx=20, pady=10)

columns = ("Threat", "Severity", "Message")
tree = ttk.Treeview(table_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
tree.pack(fill="both", expand=True)

# Chart area
chart_frame = tk.Frame(main_area, bg="white")
chart_frame.pack(fill="both", expand=True, padx=20, pady=10)

# ---------------- Functions ----------------
def run_scan():
    file_path = filedialog.askopenfilename(
        filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
    )
    if not file_path:
        return

    results = scan_file(file_path)
    issues = results["issues"]

    # Clear old table
    for row in tree.get_children():
        tree.delete(row)

    # Insert new results
    for issue in issues:
        tree.insert("", "end",
                    values=(issue["Threat"], issue["Threat Severity"], issue["Message"]))

    # Count severity levels
    severities = [i["Threat Severity"] for i in issues]
    counts = collections.Counter(severities)

    # Clear old chart
    for widget in chart_frame.winfo_children():
        widget.destroy()

    # Bar chart of severities
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.bar(counts.keys(), counts.values(),
           color=["red" if s=="High" else "orange" if s=="Medium" else "green" for s in counts.keys()])
    ax.set_title("Issues by Severity")

    canvas = FigureCanvasTkAgg(fig, master=chart_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

# ---------------- Start ----------------
root.mainloop()
