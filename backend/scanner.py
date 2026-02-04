import psutil  # running processes
from collections import Counter  # count occurrences


# -----------------------
# Helper functions
# -----------------------

def get_dir(path):
    if not path:
        return None
    # replace \ in the paths since it's Windows, then split the path
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 1:
        return None
    # return all parts except the last one (the filename)
    return "/".join(parts[:-1])
    # join() glues the parts back together with /


# -----------------------
# Main scanning logic
# -----------------------

def scan_processes():

    processes = []

    # warm up CPU stats so cpu_percent is not always 0
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=0.05)
        except psutil.Error:
            pass

    for p in psutil.process_iter([
        "pid",
        "name",
        "exe",
        "cpu_percent",
        "memory_info"
    ]):
        try:
            processes.append(p.info)
        except psutil.Error:
            continue

    # collect execution directories
    dirs = []
    for p in processes:
        d = get_dir(p.get("exe"))
        if d:
            dirs.append(d)

    dir_frequency = Counter(dirs)
    TOTAL = len(processes)

    def is_rare_path(path):  # get the rare process execution paths
        d = get_dir(path)
        if not d:
            return True
        return dir_frequency[d] / TOTAL < 0.02  # less than 2%

    alerts = []
    safe = []

    for p in processes:
        score = 0
        reasons = []

        if is_rare_path(p.get("exe")):
            score += 1
            reasons.append("rare_execution_path")

        # check if CPU usage is above 30%
        if p.get("cpu_percent") and p["cpu_percent"] > 30:
            score += 1
            reasons.append("high_cpu")

        # check if memory usage is above 300MB
        if p.get("memory_info") and p["memory_info"].rss > 300 * 1024 * 1024:
            score += 1
            reasons.append("high_memory")

        entry = {
            "pid": p["pid"],
            "name": p["name"],
            "exe": p.get("exe"),
            "score": score,
            "reasons": reasons
        }

        if score >= 2:  # threshold for alert
            alerts.append(entry)
        else:
            safe.append(entry)

    return {
        "total_processes": TOTAL,
        "alerts": alerts,
        "safe": safe
    }
