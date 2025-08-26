from tkinter import *

def start_scan():
    dashboard.insert(END, "[INFO] Scan started...\n")
    # Placeholder: later integrate vulnerability scanning logic


def load_report():
    dashboard.insert(END, "[INFO] Report loaded...\n")
    # Placeholder: later integrate report importing logic


def exit_app():
    main.destroy()


# Main window
main = Tk()
main.title("WebSET - Web Security Evaluation Tool")
main.geometry("800x500")
main.config(bg="#1e1e1e")

# Header
header = Label(main, text="WebSET Dashboard", font=("Arial", 18, "bold"), fg="white", bg="#1e1e1e")
header.pack(pady=10)

# Layout frames
left_frame = Frame(main, bg="#2b2b2b", width=200, height=400)
left_frame.pack(side=LEFT, fill=Y)

right_frame = Frame(main, bg="#ffffff", width=600, height=400)
right_frame.pack(side=RIGHT, fill=BOTH, expand=True)

# Buttons on left panel
btn_scan = Button(left_frame, text="Start Scan", command=start_scan, width=20, bg="#3a3a3a", fg="white")
btn_scan.pack(pady=10)

btn_report = Button(left_frame, text="Load Report", command=load_report, width=20, bg="#3a3a3a", fg="white")
btn_report.pack(pady=10)

btn_exit = Button(left_frame, text="Exit", command=exit_app, width=20, bg="#a83232", fg="white")
btn_exit.pack(pady=10)

# Dashboard (right panel)
dashboard_label = Label(right_frame, text="Scan Dashboard", font=("Arial", 14), bg="#ffffff")
dashboard_label.pack(pady=5)

dashboard = Text(right_frame, wrap=WORD, font=("Courier", 10))
dashboard.pack(fill=BOTH, expand=True, padx=10, pady=10)

main.mainloop()
