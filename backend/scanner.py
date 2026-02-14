import psutil
from collections import Counter, defaultdict
import time
import os
from db import Database
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import hashlib
import json
import platform
import re

db = Database()

file_activity_by_pid = defaultdict(int)
file_activity_global = 0
lock = threading.Lock()

_scan_cache = {
    "last_scan_time": 0,
    "last_result": None,
    "cache_duration": 5
}

# Hash databases
malware_hashes = {
    "sha256": {},
    "md5": {},
    "sha1": {}
}

def load_malware_hashes():
    """Load malware hashes from JSON file"""
    global malware_hashes
    
    for json_file in ["malware_hashes_comprehensive.json", "malware_hashes.json"]:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                data.pop('_metadata', None)
                data.pop('README', None)
                data.pop('INFO', None)
                
                malware_hashes["sha256"] = data
                print(f"Loaded {len(data)} SHA256 malware signatures")
                return
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
    
    print(f"Warning: No malware hash database found")

load_malware_hashes()

# Whitelisted directory patterns
WHITELISTED_PATTERNS = [
    r'C:\\Windows\\System32', r'C:\\Windows\\SystemApps', 
    r'C:\\Program Files\\WindowsApps', r'C:\\Program Files\\Microsoft',
    r'C:\\Program Files\\Common Files\\microsoft shared',
    r'C:\\Windows\\WinSxS',
    r'C:\\Program Files\\PostgreSQL',
    r'C:\\Program Files\\PgBouncer',
    r'C:\\Program Files\\ReasonLabs',
    r'C:\\Program Files\\edb',
    r'C:\\Program Files \(x86\)\\Hard Disk Sentinel'
]

WHITELISTED_REGEX = [re.compile(pattern, re.IGNORECASE) for pattern in WHITELISTED_PATTERNS]

def is_whitelisted_path(path):
    """Check if path is whitelisted"""
    if not path:
        return False
    
    for regex in WHITELISTED_REGEX:
        if regex.search(path):
            return True
    return False

# Expanded trusted process names
TRUSTED_PROCESS_NAMES = {
    'searchhost.exe', 'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
    'textinputhost.exe', 'lockapp.exe', 'systemsettings.exe',
    'explorer.exe', 'tiworker.exe', 'trustedinstaller.exe',
    'svchost.exe', 'services.exe', 'lsass.exe', 'csrss.exe',
    'appvshnotify.exe', 'officeclicktorun.exe', 'cmd.exe',
    'code.exe', 'node.exe', 'python.exe', 'bash.exe',
    'postgres.exe', 'pg_ctl.exe', 'pgbouncer.exe',
    'hdsentinel.exe', 'servicewrapper.exe', 'rsvpnclientsvc.exe'
}

def is_trusted_process(name, path):
    """Check if process is trusted"""
    if not name:
        return False
    
    name_lower = name.lower()
    
    if name_lower in TRUSTED_PROCESS_NAMES:
        return True
    
    return is_whitelisted_path(path)

def calculate_file_hash_fast(filepath):
    """Fast SHA256 hash - only first 1MB"""
    if not filepath or not os.path.isfile(filepath):
        return None
    
    try:
        file_size = os.path.getsize(filepath)
        
        if file_size > 100*1024*1024:  # Skip files > 100MB
            return {"size": file_size, "too_large": True}
        
        sha256_obj = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            # Only read first 1MB for speed
            chunk = f.read(1024 * 1024)
            sha256_obj.update(chunk)
        
        return {
            "sha256": sha256_obj.hexdigest(),
            "size": file_size
        }
    except Exception as e:
        return None

def check_malware_fast(filepath):
    """Fast malware check - only hash matching"""
    detection_info = {
        "hash_match": False,
        "details": []
    }
    
    # Quick hash check
    hashes = calculate_file_hash_fast(filepath)
    if not hashes or hashes.get("too_large"):
        return False, detection_info, hashes
    
    # Only check SHA256 hash
    hash_value = hashes.get("sha256")
    if hash_value and hash_value in malware_hashes.get("sha256", {}):
        detection_info["hash_match"] = True
        malware_data = malware_hashes["sha256"][hash_value]
        name = malware_data.get('name', 'Unknown')
        detection_info["details"].append(f"EXACT HASH MATCH: {name}")
        return True, detection_info, hashes
    
    return False, detection_info, hashes

class FileEventHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return
        global file_activity_global 
        with lock:
            file_activity_global += 1

def start_file_monitoring():
    observer = Observer()
    event_handler = FileEventHandler()
    path_to_monitor = [
        os.path.expanduser("~/Documents"), 
        os.path.expanduser("~/Downloads"), 
        os.path.expanduser("~/Desktop"),
    ] 
    for path in path_to_monitor:
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True)
    observer.daemon = True
    observer.start()
    return observer

def get_dir(path):
    if not path:
        return None
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 1:
        return None
    return "/".join(parts[:-1])

def scan_processes(force_refresh=False):
    """FAST scanning function - only hash checks"""
    global _scan_cache, file_activity_by_pid, file_activity_global
    
    current_time = time.time()
    if not force_refresh and _scan_cache["last_result"] is not None:
        time_since_last = current_time - _scan_cache["last_scan_time"]
        if time_since_last < _scan_cache["cache_duration"]:
            print(f"Using cached scan results ({time_since_last:.1f}s old)")
            return _scan_cache["last_result"]
    
    print("Starting fast malware scan...")
    start_time = time.time()
    
    processes = []
    all_processes_count = 0
    
    # Quick process collection - NO CPU warmup
    for p in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'num_threads']):
        try:
            all_processes_count += 1
            
            info = p.info
            exe = info.get('exe')
            name = info.get('name')
            
            if not exe:
                continue
                
            # Skip trusted processes
            if is_trusted_process(name, exe):
                continue
            
            if is_whitelisted_path(exe):
                continue
            
            processes.append(info)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    print(f"Collected {len(processes)} processes in {time.time() - start_time:.2f}s (Total: {all_processes_count})")
    
    # Calculate directory frequency
    dirs = []
    for p in processes:
        d = get_dir(p.get("exe"))
        if d:
            dirs.append(d)

    dir_frequency = Counter(dirs)

    def is_rare_path(path):
        d = get_dir(path)
        if not d:
            return True
        if len(processes) == 0:
            return True
        return dir_frequency[d] / len(processes) < 0.05

    alerts = []
    safe = []
    seen_pids = set()

    print(f"Analyzing {len(processes)} processes...")
    analyzed = 0
    
    for p in processes:
        score = 0
        reasons = []
        detection_details = []
        file_hashes = None
        
        exe_path = p.get("exe")
        name = p.get("name")
        pid = p.get("pid")

        if is_trusted_process(name, exe_path):
            continue

        # FAST malware check - only hash
        is_malware, detection_info, file_hashes = check_malware_fast(exe_path)
        
        if is_malware:
            score += 10
            reasons.append("confirmed_malware_hash")
            detection_details = detection_info["details"]
            print(f"THREAT DETECTED: {name} - {', '.join(detection_details)}")

        # Only check rare path for non-malware
        if score == 0 and is_rare_path(exe_path):
            score += 0.5
            reasons.append("rare_path")

        # Determine severity
        if detection_info.get("hash_match"):
            severity = "confirmed_malware"
        elif score >= 5:
            severity = "critical"
        elif score >= 3:
            severity = "warning"
        elif score >= 1:
            severity = "suspicious"
        else:
            severity = "info"

        entry = {
            "id": pid,
            "pid": pid,
            "name": name or "Unknown",
            "path": exe_path or "N/A",
            "score": score,
            "reasons": reasons,
            "severity": severity,
            "time": time.strftime("%H:%M:%S"),
            "status": "detected" if severity in ["confirmed_malware", "critical", "warning", "suspicious"] else "safe",
            "malware_info": detection_details if detection_details else None,
            "file_hash": file_hashes.get("sha256") if file_hashes else None,
            "hashes": file_hashes
        }
        
        if pid in seen_pids:
            continue
        seen_pids.add(pid)

        if severity in ["confirmed_malware", "critical", "warning", "suspicious"]:
            alerts.append(entry)
        else:
            safe.append(entry)
        
        analyzed += 1
        if analyzed % 50 == 0:
            print(f"  Analyzed {analyzed}/{len(processes)}...")

    result = {
        "total_processes": all_processes_count,
        "alerts": alerts,
        "safe": safe,
        "processes": processes
    }
    
    _scan_cache["last_scan_time"] = current_time
    _scan_cache["last_result"] = result
    
    elapsed = time.time() - start_time
    confirmed = len([a for a in alerts if a['severity'] == 'confirmed_malware'])
    critical = len([a for a in alerts if a['severity'] == 'critical'])
    warning = len([a for a in alerts if a['severity'] == 'warning'])
    suspicious = len([a for a in alerts if a['severity'] == 'suspicious'])
    
    print(f"Scan complete in {elapsed:.2f}s: {confirmed} confirmed, {critical} critical, {warning} warning, {suspicious} suspicious")
    
    return result

def stream_processes():
    """Stream processes for UI"""
    count = 0
    for p in psutil.process_iter(['pid', 'name', 'exe', 'memory_info']):
        try:
            info = p.info
            mem = info['memory_info'].rss / (1024 * 1024) if info.get('memory_info') else 0
            
            yield {
                "type": "process_info",
                "data": {
                    "PID": info.get('pid', 0),
                    "Name": info.get('name') or "Unknown",
                    "Memory": f"{mem:.2f} MB",
                    "Path": info.get('exe') or "N/A"
                },
                "status": "streaming"
            }
            count += 1
            time.sleep(0.005)  # Very short delay
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    yield {
        "type": "complete",
        "data": {"total_count": count},
        "status": "complete"
    }

def store_scan_results(scan_data):
    """Store scan results to database"""
    print("Storing scan results to database...")
    
    scan_id = db.create_scan(scan_type="quick")
    print(f"Created scan with ID: {scan_id}")
    
    try:
        pid_to_uuid = {}
        
        for p in scan_data['processes']:
            mem_info = p.get("memory_info")
            memory_mb = mem_info.rss / (1024 * 1024) if mem_info else 0
            
            alert = next((a for a in scan_data['alerts'] if a['pid'] == p['pid']), None)
            
            process_uuid = db.log_process(
                scan_id=scan_id,
                process_id=p['pid'],
                name=p.get('name') or 'Unknown',
                path=p.get('exe') or 'N/A',
                score=alert['score'] if alert else 0,
                threads=p.get('num_threads', 0),
                connections=0,
                reasons=alert['reasons'] if alert else [],
                severity=alert['severity'] if alert else 'info',
                signed=False,
                cpu_usage=0,
                memory_usage=memory_mb
            )
            
            if process_uuid:
                pid_to_uuid[p['pid']] = process_uuid
        
        print(f"Logged {len(scan_data['processes'])} processes")
        
        alerts_logged = 0
        for alert in scan_data['alerts']:
            pid = alert['pid']
            process_uuid = pid_to_uuid.get(pid)
            
            if process_uuid:
                if alert['severity'] == 'confirmed_malware':
                    title = f"CONFIRMED MALWARE: {alert['name']}"
                else:
                    title = f"Suspicious Process: {alert['name']}"
                
                db.log_alert(
                    scan_id=scan_id,
                    process_uuid=process_uuid,
                    severity=alert['severity'],
                    title=title,
                    path=alert['path'],
                    score=alert['score'],
                    reasons=alert['reasons']
                )
                alerts_logged += 1
        
        print(f"Logged {alerts_logged}/{len(scan_data['alerts'])} alerts")
        
        total_alerts = len(scan_data['alerts'])
        confirmed_malware = len([a for a in scan_data['alerts'] if a['severity'] == 'confirmed_malware'])
        critical_alerts = len([a for a in scan_data['alerts'] if a['severity'] == 'critical'])
        high_alerts = len([a for a in scan_data['alerts'] if a['severity'] == 'warning'])
        
        risk_score = (confirmed_malware * 100) + (critical_alerts * 10) + (high_alerts * 5) + (total_alerts * 2)
        
        if confirmed_malware > 0:
            risk_level = "critical"
        elif risk_score >= 30:
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
        
        print(f"Scan completed with risk level: {risk_level} (score: {risk_score})")
        return scan_id
        
    except Exception as e:
        print(f"Error storing scan results: {e}")
        import traceback
        traceback.print_exc()
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

if __name__ == "__main__":
    observer = start_file_monitoring()
    print("=" * 60)
    print("FAST MALWARE SCANNER")
    print("=" * 60)
    print(f"Loaded {len(malware_hashes['sha256'])} SHA256 signatures")
    print("=" * 60)
    
    print("Running scan...")
    result = scan_processes(force_refresh=True)
    print(f"\nScan Summary:")
    print(f"Total processes: {result['total_processes']}")
    print(f"Total alerts: {len(result['alerts'])}")
    print(f"Safe processes: {len(result['safe'])}")
    
    if result['alerts']:
        print("\nALERTS:")
        for alert in result['alerts']:
            print(f"[{alert['severity'].upper()}] {alert['name']} (PID {alert['pid']})")
            if alert.get('malware_info'):
                for detail in alert['malware_info'][:3]:
                    print(f"     -> {detail}")
            print()
    
    print("\nMonitoring files... Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("\nScanner stopped.")