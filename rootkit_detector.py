import psutil
import subprocess
import os
from datetime import datetime

REPORT_FILE = "rootkit_report.txt"

def log(text, file):
    print(text)
    file.write(text + "\n")

def get_psutil_processes():
    return set(p.name() for p in psutil.process_iter(['name']))

def get_tasklist_processes():
    result = subprocess.run(['tasklist'], capture_output=True, text=True)
    lines = result.stdout.splitlines()[3:]  # Skip headers
    tasklist_processes = set()
    for line in lines:
        if line:
            name = line.split()[0]
            tasklist_processes.add(name)
    return tasklist_processes

def detect_hidden_processes(report):
    log("=== Checking for Hidden Processes ===", report)
    psutil_procs = get_psutil_processes()
    tasklist_procs = get_tasklist_processes()
    
    hidden = tasklist_procs - psutil_procs
    if hidden:
        log("[!!] Possible hidden processes detected:", report)
        for proc in hidden:
            log(f"  - {proc}", report)
    else:
        log("[OK] No hidden processes detected.", report)
    log("", report)

def check_startup_entries(report):
    log("=== Checking Windows Startup Folders ===", report)
    startup_dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    ]

    for path in startup_dirs:
        log(f"Folder: {path}", report)
        if os.path.exists(path):
            files = os.listdir(path)
            if files:
                for file in files:
                    log(f"  - Startup item: {file}", report)
            else:
                log("  (Empty)", report)
        else:
            log("  (Folder not found)", report)
    log("", report)

def create_report():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"rootkit_report_{timestamp}.txt"
    with open(filename, "w") as report:
        log(f"Rootkit Detector Report - {timestamp}", report)
        log("="*40, report)
        detect_hidden_processes(report)
        check_startup_entries(report)
        log("Scan complete.", report)
    print(f"\nReport saved as: {filename}")

if __name__ == "__main__":
    create_report()