from tkinter import *
from scanner import WebSETScanner

scanner = WebSETScanner()

def start_scan():
    text = code_box.get("1.0", END)
    if text.strip() == "":
        dashboard.insert(END, "Error: no code pasted\n")
        return
    dashboard.insert(END, "Scan started...\n")
    for f in scanner.scan_code(text, filename="<pasted>"):
        dashboard.insert(END, f"{f['severity']} - {f['title']} : {f['evidence']}\n")
    dashboard.insert(END, "Scan finished!\n")

def load_report():
    dashboard.insert(END, "Report loaded...\n")

def exit_app():
    root.destroy()

root = Tk()
root.title("WebSET")
root.geometry("800x500")
root.config(bg="lightblue")

# left side buttons
left = Frame(root, bg="skyblue")
left.pack(side=LEFT, fill=Y)

# all buttons same style
btn_style = {"width": 20, "height": 2, "fg": "black", "bg": "#4fc3f7", "activebackground": "#29b6f6"}

btn1 = Button(left, text="Start Scan", command=start_scan, **btn_style)
btn1.pack(pady=5)

btn2 = Button(left, text="Load Report", command=load_report, **btn_style)
btn2.pack(pady=5)

btn3 = Button(left, text="Exit", command=exit_app, width=20, height=2,
              fg="black", bg="red", activebackground="darkred")
btn3.pack(pady=5)

# right side area
right = Frame(root, bg="white")
right.pack(side=RIGHT, fill=BOTH, expand=True)

Label(right, text="Paste Code Here:").pack()
code_box = Text(right, height=8)
code_box.pack(fill=X, padx=5, pady=5)

Label(right, text="Dashboard:").pack()
dashboard = Text(right)
dashboard.pack(fill=BOTH, expand=True, padx=5, pady=5)

root.mainloop()
