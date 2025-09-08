# file: gui.py
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

def show_dashboard():
    dashboard_page.tkraise()

def show_cases():
    cases_page.tkraise()

root = Tk()
root.title("WebSET")
root.geometry("800x500")
root.config(bg="lightblue")

# left side buttons
left = Frame(root, bg="skyblue")
left.pack(side=LEFT, fill=Y)

# button style
btn_style = {"width": 20, "height": 2, "fg": "black", "bg": "#4fc3f7", "activebackground": "#29b6f6"}

# navigation buttons
btn_dashboard = Button(left, text="Dashboard", command=show_dashboard, **btn_style)
btn_dashboard.pack(pady=5)

btn_cases = Button(left, text="Cases", command=show_cases, **btn_style)
btn_cases.pack(pady=5)

btn_load = Button(left, text="Load Report", command=load_report, **btn_style)
btn_load.pack(pady=5)

btn_exit = Button(left, text="Exit", command=exit_app, **btn_style)
btn_exit.pack(pady=5)

# right content area with stacked frames
content = Frame(root, bg="white")
content.pack(side=RIGHT, fill=BOTH, expand=True)

# dashboard page
dashboard_page = Frame(content, bg="white")
dashboard_page.place(relx=0, rely=0, relwidth=1, relheight=1)

Label(dashboard_page, text="Paste Code Here:").pack()
code_box = Text(dashboard_page, height=8)
code_box.pack(fill=X, padx=5, pady=5)

btn_start = Button(dashboard_page, text="Start Scan", command=start_scan, **btn_style)
btn_start.pack(pady=5)

Label(dashboard_page, text="Dashboard:").pack()
dashboard = Text(dashboard_page)
dashboard.pack(fill=BOTH, expand=True, padx=5, pady=5)

# cases page
cases_page = Frame(content, bg="white")
cases_page.place(relx=0, rely=0, relwidth=1, relheight=1)


Label(cases_page, text="Cases:", font=("Arial", 14, "bold")).pack(pady=10)
cases_list = Text(cases_page)
cases_list.pack(fill=BOTH, expand=True, padx=5, pady=5)
# default page
dashboard_page.tkraise()

root.mainloop()
