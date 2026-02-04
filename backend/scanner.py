import psutil #runing processes
from collections import Counter #count occurences

#process data
# -----------------------
processes = []

for p in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_info"]):
    try:
        processes.append(p.info)
    except psutil.Error:
        continue

# -----------------------
# Helper functions
# -----------------------

def get_dir(path): 
    if not path:
        return None
    parts = path.replace("\\", "/").split("/") #replace \ in the paths since it's windows and then split the path to words
    if len(parts) <= 1:
        return None
    return "/".join(parts[:-1]) #return all parts except the last one which is the filename
#join() glues the parts back together with /

def is_rare_path(path): #get the rare process execution paths
    d = get_dir(path)
    if not d:
        return True
    return dir_frequency[d] / TOTAL < 0.02  # less than 2%


def risk_score(proc): #calculate danger score for a process
    score = 0
    reasons = []

    if is_rare_path(proc["exe"]):
        score += 1
        reasons.append("rare_execution_path")

    if proc.get("cpu_percent") and proc["cpu_percent"] > 30: #check if cpu usage is above 30%
        score += 1
        reasons.append("high_cpu")

    if proc.get("memory_info") and proc["memory_info"].rss > 300 * 1024 * 1024: #check if memory usage is above 300MB
        score += 1
        reasons.append("high_memory")

    return score, reasons

# -----------------------
# Main code
# -----------------------

# Get directories
dirs = []
for p in processes:
    d = get_dir(p.get("exe")) #get the directory of each executable process
    if d:
        dirs.append(d)

# Compute frequency of each directory
dir_frequency = Counter(dirs)
TOTAL = len(processes) #total number of processes

# Compute alerts
alerts = []
for p in processes:
    score, reasons = risk_score(p)
    if score >= 2:
        alerts.append({
            "pid": p["pid"],
            "name": p["name"],
            "exe": p["exe"],
            "risk_score": score,
            "reasons": reasons
        })

# Print results
for alert in alerts:
    print(alert)
