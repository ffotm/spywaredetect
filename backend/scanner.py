import psutil
from collections import Counter
import time
import os
from db import Database
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
import threading

db = Database()

file_activity_by_pid = defaultdict(int)
file_activity_global = 0
lock = threading.Lock()

#watchdog class 
class FileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"File created: {event.src_path}")
    def on_modified(self, event):
        print(f"File modified: {event.src_path}")
    def on_deleted(self, event):
        print(f"File deleted: {event.src_path}")
    def on_moved(self, event):
        print(f"File moved: {event.src_path} to {event.dest_path}")

    
    def on_any_event(self, event):
        if event.is_directory:
            return
        global file_activity_global 
        with lock:
            file_activity_global += 1
        p = get_process_from_path(event.src_path)
        if p:
            with lock:
                file_activity_by_pid[p.pid] += 1

def start_file_monitoring():
    observer = Observer()
    event_handler = FileEventHandler()
    path_to_monitor = [os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")] 
    for path in path_to_monitor:
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True)
    observer.daemon = True
    observer.start()
    return observer
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

def get_process_from_path(path): #after watchdog gives us the path we run it here to get the process that is using this path
    for p in psutil.process_iter(['pid', 'name']):
        try:
            for f in p.open_files():
                if f.path == path:
                    return p
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None

# -----------------------
# Main scanning logic
# -----------------------


def scan_processes():

    global file_activity_by_pid, file_activity_global
    with lock:
        file_activity_by_pid_snapshot = dict(file_activity_by_pid)
        file_activity_global_snapshot = file_activity_global
        file_activity_by_pid = defaultdict(int)
        file_activity_global = 0
    
    processes = []
    process_objects = {}  #dict of objects to be able to access the processes later for more info like children and open files without having to call psutil again 

    #warming up for accumulations
    print("Warming up cpu")
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=0)  #first call init
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    # give it a moment to accumulate some cpu usage data
    time.sleep(0.5)

    #now collect actual process info
    count = 0
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
            # Get cpu percent of this specific process every 0.1
            try:
                info['cpu_percent'] = p.cpu_percent(interval=0.1)
            except:
                info['cpu_percent'] = 0
            
            # Get number of connections for this process
            try:
                info['num_connections'] = len(p.net_connections())
            except:
                info["num_connections"] = 0
                
            processes.append(info)
            process_objects[info['pid']] = p  # Store the actual Process object
            count += 1
            if count % 50 == 0:  #log for debug
                print(f"Processed {count} processes...")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    print(f"Collected {len(processes)} processes")
                
    # collect exe directories 
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
        
        # Get the actual Process object for this process
        proc_obj = process_objects.get(p["pid"])

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
            try:
                attrs = os.stat(p["exe"]).st_file_attributes
                if attrs & 0x2:  #0x2 is the flag for hidden in windows so it's comparing the attrs gotten and the flag
                   # & is used for comparison en binaire of just the flag (00000010)
                    score += 2
                    reasons.append("hidden_executable")
            except AttributeError:
                pass
        
        #7check if the process is creating child processes rapidly (more than 10 in the last minute)
        if proc_obj:
            try:
                children = proc_obj.children()
                recent_children = [c for c in children if time.time() - c.create_time() < 60]
                if len(recent_children) > 10:
                    score += 1
                    reasons.append("rapid_child_creation")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        #8check if the process is modifying files in sensitive directories (like system32 or program files)
        if proc_obj:
            try:
                for f in proc_obj.open_files():
                    if "system32" in f.path.lower() or "program files" in f.path.lower():
                        score += 2
                        reasons.append("modifying_sensitive_files")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        #9 check if the process is creating child processes with suspicious names (like "cmd.exe" or "powershell.exe")
        if proc_obj:
            try:
                for c in proc_obj.children():
                    if c.name().lower() in ["cmd.exe", "powershell.exe"]:
                        score += 1
                        reasons.append("creating_suspicious_children")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        #10 file activity monitoring
        activity_count = file_activity_by_pid_snapshot.get(p["pid"], 0)
        if activity_count > 20:  # threshold for suspicious file activity
            score += 1
            reasons.append("high_file_activity")
        if file_activity_global_snapshot > 200:  # if there's a lot of file activity overall, it could indicate a system-wide issue
            score += 1
            reasons.append("high_global_file_activity")
       

        # FIXED: Format the alert/safe entry with proper structure for frontend
        entry = {
            "id": p["pid"],
            "pid": p["pid"],
            "name": p["name"] or "Unknown",
            "path": p.get("exe") or "N/A",
            "score": score,
            "reasons": reasons,
            "severity": "critical" if score >= 4 else "warning" if score >= 3 else "info",
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

def store_scan_results(scan_data):
   
    print("Storing scan results to database...")
    
    # Create scan record
    scan_id = db.create_scan(scan_type="quick")
    print(f"Created scan with ID: {scan_id}")
    
    try:
        # Dictionary to map PID -> process UUID from database
        pid_to_uuid = {}
        
        # Log all processes FIRST (so we get their UUIDs)
        for p in scan_data['processes']:
            mem_info = p.get("memory_info")
            memory_mb = mem_info.rss / (1024 * 1024) if mem_info else 0
            cpu_percent = p.get('cpu_percent', 0)
            
            # Find if this process has an alert
            alert = next((a for a in scan_data['alerts'] if a['pid'] == p['pid']), None)
            
            # Store process and get its UUID
            process_uuid = db.log_process(
                scan_id=scan_id,
                process_id=p['pid'],
                name=p.get('name') or 'Unknown',
                path=p.get('exe') or 'N/A',
                score=alert['score'] if alert else 0,
                threads=p.get('num_threads', 0),
                connections=p.get('num_connections', 0),
                reasons=alert['reasons'] if alert else [],
                severity=alert['severity'] if alert else 'info',
                signed=False,
                cpu_usage=cpu_percent,
                memory_usage=memory_mb
            )
            
            # Map PID to the database UUID
            if process_uuid:
                pid_to_uuid[p['pid']] = process_uuid
        
        print(f"✓ Logged {len(scan_data['processes'])} processes")
        
        # Now log alerts with the correct process UUIDs
        alerts_logged = 0
        for alert in scan_data['alerts']:
            pid = alert['pid']
            process_uuid = pid_to_uuid.get(pid)
            
            if process_uuid:
                db.log_alert(
                    scan_id=scan_id,
                    process_uuid=process_uuid,  # ← Use UUID, not PID
                    severity=alert['severity'],
                    title=f"Suspicious Process: {alert['name']}",
                    path=alert['path'],
                    score=alert['score'],
                    reasons=alert['reasons']
                )
                alerts_logged += 1
            else:
                print(f"⚠ Warning: Could not find UUID for PID {pid}, skipping alert")
        
        print(f"✓ Logged {alerts_logged}/{len(scan_data['alerts'])} alerts")
        
        # Calculate risk level and complete scan
        total_alerts = len(scan_data['alerts'])
        critical_alerts = len([a for a in scan_data['alerts'] if a['severity'] == 'critical'])
        high_alerts = len([a for a in scan_data['alerts'] if a['severity'] == 'warning'])
        
        # Calculate risk score
        risk_score = (critical_alerts * 10) + (high_alerts * 5) + (total_alerts * 2)
        
        # Determine risk level
        if risk_score >= 30:
            risk_level = "critical"
        elif risk_score >= 15:
            risk_level = "high"
        elif risk_score >= 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        db.complete_scan(
            risk_level=risk_level,
            risk_score=risk_score,
            scan_id=scan_id,
            status="completed"
        )
        
        print(f"✓ Scan completed with risk level: {risk_level} (score: {risk_score})")
        return scan_id
        
    except Exception as e:
        print(f"✗ Error storing scan results: {e}")
        import traceback
        traceback.print_exc()
        # If anything fails, mark scan as failed
        try:
            db.complete_scan(
                risk_level="unknown",
                risk_score=0,
                scan_id=scan_id,
                status="failed"
            )
        except:
            pass
        raise e


# Test the function
if __name__ == "__main__":
    observer = start_file_monitoring()
    print("File monitoring started. Running scan...")
    result = scan_processes()
    print(f"\nTotal processes: {result['total_processes']}")
    print(f"Alerts: {len(result['alerts'])}")
    print(f"Safe: {len(result['safe'])}")
    if result['alerts']:
        print("\nSample alert:")
        print(result['alerts'][0])
    
    print("\nMonitoring files... Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()