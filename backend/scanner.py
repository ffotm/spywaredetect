import psutil
from collections import Counter
import time
import os

# -----------------------
# Helper functions
# -----------------------

def get_dir(path):
    if not path:
        return None
    # replace \ in the paths since it's windows then split the path by / to words
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

    # FIXED: Improved CPU warming - need longer interval for accurate readings
    print("Warming up CPU measurements...")
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=0)  # First call initializes
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    # FIXED: Wait a moment for CPU stats to accumulate
    time.sleep(0.5)

    # Now collect actual process info with real CPU values
    for p in psutil.process_iter([
        "pid",
        "name",
        "exe",
        "cpu_percent",
        "memory_info",
        "num_threads"
    ]):
        try:
            info = p.info
            # FIXED: Get CPU percent with a small interval for this specific process
            try:
                info['cpu_percent'] = p.cpu_percent(interval=0.1)
            except:
                info['cpu_percent'] = 0
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            try: 
                info['num_connections'] = len(p.connections())
            except:
                info["num_connections"] = 0
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
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

        #1 check if execution path is rare
        if is_rare_path(p.get("exe")):
            score += 1
            reasons.append("rare_execution_path")

        #2 check if CPU usage is above 30%
        cpu = p.get("cpu_percent", 0)
        if cpu and cpu > 30:
            score += 1
            reasons.append("high_cpu")

        #3 check if memory usage is above 300MB
        mem_info = p.get("memory_info")
        if mem_info and mem_info.rss > 300 * 1024 * 1024:
            score += 1
            reasons.append("high_memory")
        #4 check if number of threads is above 50
        threads = p.get("num_threads", 0)
        if threads and threads > 50:
            score += 1
            reasons.append("high_threads")
        #5 check if number of connections is above 100
        connections = p.get("num_connections", 0)
        if connections and connections > 100:
            score += 1
            reasons.append("high_connections")
        #6 check if the process executable is hidden
        if p.get("exe") and os.path.isfile(p["exe"]):
            attrs = os.stat(p["exe"]).st_file_attributes
            if attrs & 0x2:  #thats the flag for hidden in windows so it's comparing the attrs gotten and the flag
               #& is used for comparison en binaire of just the flag (00000010)
                score += 2
                reasons.append("hidden_executable")

        # FIXED: Format the alert/safe entry with proper structure for frontend
        entry = {
            "id": p["pid"],
            "pid": p["pid"],
            "name": p["name"] or "Unknown",
            "path": p.get("exe") or "N/A",
            "score": score,
            "reasons": reasons,
            "severity": "critical" if score >= 3 else "high" if score >= 2 else "medium",
            "time": time.strftime("%H:%M:%S"),
            "status": "detected" if score >= 2 else "safe"
        }

        if score >= 2:  # threshold for alert
            alerts.append(entry)
        else:
            safe.append(entry)

    return {
        "total_processes": TOTAL,
        "alerts": alerts,
        "safe": safe,
        "processes": processes
    }

def stream_processes():
    for p in psutil.process_iter(['pid', 'name', 'exe', 'memory_info']):
        try:
            mem = p.info['memory_info'].rss / (1024 * 1024) #the size in the ram converted to MB (Resident Set Size)
            yield {
                "type": "process_info",
                "data": {
                    "PID": p.info['pid'],
                    "Name": p.info['name'] or "Unknown",
                    "Memory": f"{mem:.2f} MB",
                    "Path": p.info['exe'] or "N/A"
                },
                "status": "streaming"
            }
            time.sleep(0.05)  # Slower for visibility
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    # Send completion signal
    yield {
        "type": "complete",
        "data": {},
        "status": "complete"
    }


# Test the function
if __name__ == "__main__":
    result = scan_processes()
    print(f"\nTotal processes: {result['total_processes']}")
    print(f"Alerts: {len(result['alerts'])}")
    print(f"Safe: {len(result['safe'])}")
    
    if result['alerts']:
        print("\nSample alert:")
        print(result['alerts'][0])