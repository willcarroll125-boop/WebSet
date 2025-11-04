# scanner.py

import os
import json
import re
import csv
from bs4 import BeautifulSoup
from collections import Counter
import matplotlib.pyplot as plt
from pdfgen import generate_pdf

def scan_file(file):
    ext = os.path.splitext(file)[1].lower()
    issues = []

    if ext in [".html", ".htm"]: #HTML
        with open(file, "r", encoding="utf-8") as f:
            html_code = f.read()
        html_clean = BeautifulSoup(html_code, "html.parser")

        issues.extend(BrokenAccessControl(html_clean))
        issues.extend(sql_Injection(html_clean))
        issues.extend(SecurityMisconfiguration(html_clean))
        issues.extend(Identification_and_Authentication_failures(html_clean))
        issues.extend(Vulnerable_and_Outdated_Components(html_clean))


    elif ext in [".java", ".js"]:  # JAVA/JS
        with open(file, "r", encoding="utf-8") as f:
            code = f.read()

        java_clean = re.sub(r"//.*|/\*[\s\S]*?\*/", "", code)
        java_clean = re.sub(r"\s+", " ", java_clean).strip()

        issues.extend(BrokenAccessControl_JS(java_clean))
        issues.extend(CryptographicFailures_JS(java_clean))
        issues.extend(sql_Injection_JS(java_clean))
        issues.extend(SecurityMisconfiguration_JS(java_clean))
        issues.extend(Identification_and_Authentication_failures_JS(java_clean))
        issues.extend(Software_and_Data_Integrity_JS(java_clean))
        issues.extend(Security_Logging_and_Monitoring_JS(java_clean))
        issues.extend(SSRF_JS(java_clean))

    return {"issues": issues}


# HTML scanners

def BrokenAccessControl(html_clean):
    issues = []
    for div in html_clean.find_all("div", id=True):
        if "admin" in div.get("id", "").lower():
            issues.append({"Threat": "Broken Access Control","Threat Severity": "High", "Message": "Hidden admin functionality found in page." })
    for inp in html_clean.find_all("input", {"type": "hidden"}):
        if any(k in inp.get("name","").lower() for k in ["key","token","secret","api"]):
            issues.append({"Threat": "Broken Access Control","Threat Severity": "High", "Message": "Hardcoded credential or API key found in form."})
    for a in html_clean.find_all("a", href=True):
        if re.search(r"/user/\w+|/admin/\w+", a["href"].lower()):
            issues.append({"Threat": "Broken Access Control","Threat Severity": "Medium", "Message": "Direct object reference in link"})
    return issues

def sql_Injection(html_clean):
    issues = []
    for div in html_clean.find_all("div", id=True):
        if "{{" in div.get_text() or "{{" in div.decode_contents():
            issues.append({"Threat": "Injection", "Threat Severity": "High", "Message": "SQL Injection - Direct user input rendering detected."})
    for script in html_clean.find_all("script"):
        code = script.get_text().lower()
        if "{{" in code:
            issues.append({"Threat": "Injection", "Threat Severity": "High", "Message": "SQL Injection - Template placeholder detected — possible injection."})
    for tag in html_clean.find_all(True):
        for attr, val in tag.attrs.items():
            if isinstance(val, list):
                val = " ".join(val)
            if "{{" in str(val):
                sev = "High" if attr in ["src", "href", "onerror", "onclick"] else "Medium"
                issues.append({"Threat": "Injection", "Threat Severity": sev, "Message": "SQL Injection - Unsafe template placeholder in attribute"})
    return issues

def SecurityMisconfiguration(html_clean):
    issues = []
    for script in html_clean.find_all("script"):
        code = script.get_text().lower()
        if "disable security" in code or "allow all origins" in code:
            issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "High", "Message": "Code appears to disable security restrictions."})
    meta_tags = [m.get("http-equiv", "").lower() for m in html_clean.find_all("meta")]
    if not any("content-security-policy" in m for m in meta_tags):
        issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "Medium", "Message": "No Content-Security-Policy meta tag detected."})
    return issues

def Identification_and_Authentication_failures(html_clean):
    issues = []
    for script in html_clean.find_all("script"):
        code = script.get_text().lower()
        if re.search(r"(username|user|login|password)\s*=\s*['\"]", code):
            issues.append({ "Threat": "Identity and Authentication Failures", "Threat Severity": "High", "Message": "Possible hard-coded username or password."})
        if "basic auth" in code or "default credentials" in code:
            issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "Medium", "Message": "Basic or default authentication found in script."})
    for inp in html_clean.find_all("input"):
        if inp.get("type", "").lower() == "password" and not inp.get("autocomplete"):
            issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "Low", "Message": "Password field missing 'autocomplete' attribute."})
    return issues

def Vulnerable_and_Outdated_Components(html_clean):
    issues = []
    for script in html_clean.find_all("script"):
        code = script.get_text().lower()
        if "jquery-1." in code or "jquery-2." in code:
            issues.append({"Threat": "Vulnerable/Outdated Component", "Threat Severity": "High", "Message": "Old jQuery detected"})
        if "angular-1." in code:
            issues.append({"Threat": "Vulnerable/Outdated Component", "Threat Severity": "High", "Message": "Old AngularJS detected"})
        if "lodash@3" in code:
            issues.append({"Threat": "Vulnerable/Outdated Component", "Threat Severity": "Medium", "Message": "Old Lodash detected"})
        if "node_modules" in code or "dev-dependency" in code:
            issues.append({"Threat": "Vulnerable/Outdated Component", "Threat Severity": "High", "Message": "Dev dependency in production"})
        if code.startswith("http") and not script.has_attr("integrity"):
            issues.append({"Threat": "Vulnerable/Outdated Component", "Threat Severity": "Medium", "Message": "CDN script without integrity"})
    return issues


# JAVA scanners

def BrokenAccessControl_JS(java_clean):
    issues = []
    if "user.role === 'admin'" in java_clean:
        issues.append({"Threat": "Broken Access Control", "Threat Severity": "High", "Message": "Client-side role check detected — possible broken access control."})
    if any(k in java_clean for k in ["API_KEY=", "authToken=", "token=", "secret="]):
        issues.append({"Threat": "Broken Access Control", "Threat Severity": "High", "Message": "Hardcoded credential or API key detected in code."})
    if "/api/" in java_clean or "/admin/" in java_clean:
        issues.append({"Threat": "Broken Access Control", "Threat Severity": "Medium", "Message": "Direct object reference detected — possible insecure access."})
    if "currentUser.id" in java_clean or "targetUser.id" in java_clean:
        issues.append({"Threat": "Broken Access Control", "Threat Severity": "Medium", "Message": "Role-based logic detected — missing server-side check possible."})
    if "urlParams.get(" in java_clean and "=== 'true'" in java_clean:
        issues.append({"Threat": "Broken Access Control", "Threat Severity": "Medium", "Message": "Insecure parameter handling detected."})
    return issues

def CryptographicFailures_JS(java_clean):
    issues = []
    weak_algos = ["md5","sha1", "des", "3des", "rc4"]
    for algo in weak_algos:
        if algo in java_clean:
            issues.append({"Threat": "Cryptographic Failure", "Threat Severity": "High", "Message": "Weak algorithm"})
    if any(k in java_clean for k in ["encryptionKey=", "salt=", "key=", "secret="]):
        issues.append({"Threat": "Cryptographic Failure", "Threat Severity": "High", "Message": "Hardcoded key/salt detected"})
    if "Math.random(" in java_clean or "Date.now(" in java_clean:
        issues.append({"Threat": "Cryptographic Failure", "Threat Severity": "Medium", "Message": "Weak random generation"})
    if "localStorage.setItem(" in java_clean or "sessionStorage.setItem(" in java_clean:
        issues.append({"Threat": "Cryptographic Failure","Threat Severity": "Medium", "Message": "Sensitive data stored in web storage"})
    if "fetch(" in java_clean and "http://" in java_clean:
        issues.append({"Threat": "Cryptographic Failure", "Threat Severity": "High", "Message": "Sensitive data sent over HTTP"})
    return issues

def sql_Injection_JS(java_clean):
    issues = []
    patterns = {
        "SQL Injection": ["select ", "insert ", "update ", "delete ", "drop ", "union "],
        "XSS / DOM Injection": ["document.getElementById", "innerHTML=", "outerHTML=", ".html("],
        "Command Injection": ["exec(", "system(", "eval(", "Function(", "setTimeout("]}
    for threat, checks in patterns.items():
        for check in checks:
            if check in java_clean:
                sev = "High" if "SQL" in threat or "Command" in threat else "Medium"
                issues.append({"Threat":"Injection", "Threat Severity":sev, "Message": f"Possible {threat} detected"})
    return issues

def SecurityMisconfiguration_JS(java_clean):
    issues = []
    if "authenticateUser(" in java_clean:
        issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "High", "Message": "No rate limiting detected — direct authentication without throttling"})
    if "processPayment(" in java_clean:
        issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "High", "Message": "Insufficient validation detected — missing upper limit or currency check"})
    if "applyDiscount(" in java_clean:
        issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "Medium", "Message": "Potential discount calculation flaw — missing validation of discount range"})
    if "content-security-policy" not in java_clean and "hsts" not in java_clean:
        issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "Medium", "Message": "Missing security headers detected — CSP or HSTS not implemented"})
    if "console.log(" in java_clean or "alert(" in java_clean:
        issues.append({"Threat": "Security Misconfiguration", "Threat Severity": "High", "Message": "Sensitive error information disclosure — console.log or alert used"})
    return issues

def Identification_and_Authentication_failures_JS(java_clean):
    issues = []
    if "password.length<" in java_clean:
        issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "High", "Message": "Weak password length check detected"})
    if "localStorage.setItem('sessionToken'" in java_clean:
        issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "Medium", "Message": "Session token stored in localStorage"})
    if "sessionStorage.setItem(" in java_clean:
        issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "Medium", "Message": "Session data stored insecurely"})
    if "password=" in java_clean:
        issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "High", "Message": "Password hardcoded in client-side code"})
    if "btoa(" in java_clean:
        issues.append({"Threat": "Identity and Authentication Failures", "Threat Severity": "Medium", "Message": "Weak token generation detected"})
    return issues

def Software_and_Data_Integrity_JS(java_clean):
    issues = []
    if "<script" in java_clean and "src=" in java_clean and "integrity=" not in java_clean:
        issues.append({"Threat": "Software and Data Integrity Failures", "Threat Severity": "High", "Message": "External script without Subresource Integrity (SRI) detected"})
    if "JSON.parse(" in java_clean:
        issues.append({"Threat": "Software and Data Integrity Failures", "Threat Severity": "High", "Message": "Deserialization of untrusted input detected"})
    if "eval(" in java_clean:
        issues.append({"Threat": "Software and Data Integrity Failures", "Threat Severity": "High", "Message": "eval() usage detected — unsafe deserialization possible"})
    if "require(" in java_clean:
        issues.append({"Threat": "Software and Data Integrity Failures", "Threat Severity": "High","Message": "Dynamic plugin loading detected"})
    if "document.createElement('script')" in java_clean:
        issues.append({"Threat": "Software and Data Integrity Failures", "Threat Severity": "Medium", "Message": "Script dynamically created from untrusted source"})
    return issues

def Security_Logging_and_Monitoring_JS(java_clean):
    issues = []
    if "function login(" in java_clean and not any(k in java_clean for k in ["log", "logger", "audit"]):
        issues.append({"Threat": "Security logging and Monitoring Failures", "Threat Severity": "High", "Message": "Login function without security logging detected"})
    if ("console.log(" in java_clean or "console.error(" in java_clean) and any(k in java_clean for k in ["password", "user"]):
        issues.append({"Threat": "Security logging and Monitoring Failures", "Threat Severity": "High", "Message": "Sensitive information logged to console"})
    return issues

def SSRF_JS(java_clean):
    issues = []
    if "fetch(url)" in java_clean:
        issues.append({"Threat": "Server-Side Request Forgery", "Threat Severity":"High", "Message": "User-controlled URL fetch without validation"})
    if "axios.get" in java_clean and "proxyRequest(" in java_clean:
        issues.append({"Threat": "Server-Side Request Forgery", "Threat Severity":"High", "Message": "Proxy request to user-controlled URL without validation"})
    if "new Image(" in java_clean and ".src=" in java_clean:
        issues.append({"Threat": "Server-Side Request Forgery", "Threat Severity":"Medium", "Message": "User-controlled image source loading detected"})
    if "callWebhook(" in java_clean and "fetch(" in java_clean:
        issues.append({"Threat": "Server-Side Request Forgery", "Threat Severity":"High", "Message": "Webhook call with user-controlled URL detected"})
    return issues



## END of Vulnerability Scanner section - Start of Report Writing Section ##
def csv_output(results, filename="WebSETResults.csv"):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["Threat", "Threat Severity", "Message"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for issue in results["issues"]:
            writer.writerow(issue)

def severityGraph(results):
    amount = Counter()
    for issue in results.get("issues", []):
        severity = (issue.get("Threat Severity") or "").strip()
        if severity:
            amount[severity] += 1
    return amount

def threatCount(results):
    amount = Counter()
    for issues in results.get("issues", []):
        name = (issues.get("Threat") or "").strip()
        if name:
            amount[name] += 1
    return amount

def sevBarGraph(results, out_path= "sevBarGraph.png"):
    counts = severityGraph(results)
    if not counts:
        print("No vulnerable components found")
        return
    labels = list(counts.keys())
    values = list(counts.values())
    plt.bar(labels, values)
    plt.title("Findings by Severity")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.savefig(out_path)
    plt.close()

def threatCountGraph(results, out_path= "threatCountGraph.png"):
    counts = threatCount(results)
    if not counts:
        print("No vulnerable components found")
        return
    labels = list(counts.keys())
    values = list(counts.values())
    plt.bar(labels, values)
    plt.title("Findings by Threat Type")
    plt.xlabel("Threat")
    plt.ylabel("Count")
    plt.savefig(out_path)
    plt.close()

if __name__ == "__main__":
    output = scan_file("sample.html")
    print(json.dumps(output, indent=4))
    csv_output(output, "WebSETResults.csv")
    sevBarGraph(output, "severity_bar.png")
    threatCountGraph(output, "threats_bar.png")
    generate_pdf(output, "WebSET_Report.pdf", "severity_bar.png", "threats_bar.png")

    print("Results written to file")
