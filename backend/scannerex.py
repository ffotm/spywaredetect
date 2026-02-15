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

# ========== Cache to prevent duplicate scans ==========
_scan_cache = {
    "last_scan_time": 0,
    "last_result": None,
    "cache_duration": 5
}

# ========== Multi-hash malware database ==========
malware_hashes = {
    "sha256": {},
    "md5": {},
    "sha1": {},
    "imphash": {}  # Import hash for PE files
}

def load_malware_hashes():
    """Load malware hashes from JSON file and build multiple hash indexes"""
    global malware_hashes
    
    for json_file in ["malware_hashes_comprehensive.json", "malware_hashes.json"]:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                data.pop('_metadata', None)
                data.pop('README', None)
                data.pop('INFO', None)
                
                # Build SHA256 index (from your existing file)
                malware_hashes["sha256"] = data
                
                print(f"✓ Loaded {len(data)} SHA256 malware signatures from {json_file}")
                return
            except Exception as e:
                print(f"✗ Error loading {json_file}: {e}")
    
    print(f"⚠ Warning: No malware hash database found")

load_malware_hashes()

# ========== YARA-like signature patterns ==========
MALWARE_SIGNATURES = {
    "suspicious_strings": [
        b"keylogger",
        b"ransomware", 
        b"cryptolocker",
        b"mimikatz",
        b"metasploit",
        b"cobalt strike",
        b"empire",
        b"powershell empire",
        b"invoke-mimikatz",
        b"invoke-shellcode",
        b"get-credential",
        b"lsadump",
        b"procdump",
        b"sekurlsa",
        b"backdoor",
        b"rootkit",
        b"payload",
        b"exploit",
        b"shellcode"
    ],
    "packer_signatures": [
        b"UPX",  # UPX packer
        b"MPRESS",  # MPRESS packer
        b"PECompact",
        b"ASPack",
        b"Themida"
    ],
    "suspicious_apis": [
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"SetWindowsHookEx",
        b"GetAsyncKeyState",  # Keylogging
        b"CryptEncrypt",  # Ransomware
        b"RegSetValueEx",  # Registry modification
        b"URLDownloadToFile",  # Download capability
        b"WinExec",
        b"ShellExecute"
    ]
}

# ========== Suspicious file name patterns ==========
SUSPICIOUS_FILENAMES = [
    r".*\.(exe|scr|pif|com|bat|cmd|vbs|js|jar|wsf)\.exe$",  # Double extension
    r"^(invoice|document|report|photo|video|order|payment|receipt|shipping)\.(exe|scr|pif)$",
    r"^(setup|install|crack|keygen|patch|activator).*\.(exe|scr|pif)$",
    r"^(chrome|firefox|edge|flash|java|adobe).*update.*\.(exe|scr|pif)$",
    r".*codec.*\.(exe|scr|pif)$",
    r".*player.*update.*\.(exe|scr|pif)$",
]

# Compile regex patterns for performance
SUSPICIOUS_FILENAME_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_FILENAMES]

# ========== Dynamic trusted paths ==========
def get_trusted_paths():
    """Get trusted system paths dynamically"""
    trusted = set()
    system = platform.system()
    
    if system == "Windows":
        windir = os.environ.get('WINDIR', 'C:\\Windows')
        progfiles = os.environ.get('ProgramFiles', 'C:\\Program Files')
        progfiles_x86 = os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')
        appdata = os.environ.get('LOCALAPPDATA', '')
        
        # Core Windows processes
        trusted.add(os.path.join(windir, "explorer.exe").lower())
        trusted.add(os.path.join(windir, "System32", "svchost.exe").lower())
        trusted.add(os.path.join(windir, "System32", "lsass.exe").lower())
        trusted.add(os.path.join(windir, "System32", "csrss.exe").lower())
        trusted.add(os.path.join(windir, "System32", "services.exe").lower())
        trusted.add(os.path.join(windir, "System32", "wininit.exe").lower())
        
        # Common legitimate apps
        common_apps = [
            os.path.join(progfiles, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(progfiles_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(appdata, "Programs", "Microsoft VS Code", "Code.exe"),
        ]
        
        for app in common_apps:
            if os.path.exists(app):
                trusted.add(app.lower())
    
    elif system == "Linux":
        trusted.update([
            "/usr/bin/systemd", "/usr/bin/bash", "/usr/bin/python3"
        ])
    
    return trusted

trusted_processes_paths = get_trusted_paths()

# ========== Whitelisted patterns ==========
WHITELISTED_PATTERNS = [
    r'C:\\Windows\\System32',
    r'C:\\Windows\\SystemApps',
    r'C:\\Windows\\ImmersiveControlPanel',
    r'C:\\Program Files\\WindowsApps',
    r'C:\\Program Files\\Microsoft OneDrive',
    r'C:\\Program Files\\CONEXANT',
    r'C:\\Program Files\\Synaptics',
    r'Microsoft VS Code',
    r'\\Git\\',
    r'\\nodejs\\',
    r'\\Python\\',
    r'\\.vscode\\extensions',
    r'SpotifyAB\\.SpotifyMusic',
    r'Opera GX',
    r'WOMic',
]

WHITELISTED_REGEX = [re.compile(pattern, re.IGNORECASE) for pattern in WHITELISTED_PATTERNS]

def is_whitelisted_path(path):
    """Check if path matches any whitelisted pattern"""
    if not path:
        return False
    
    for regex in WHITELISTED_REGEX:
        if regex.search(path):
            return True
    return False

# ========== Trusted process names ==========
TRUSTED_PROCESS_NAMES = {
    'searchhost.exe', 'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
    'textinputhost.exe', 'lockapp.exe', 'widgetservice.exe', 'widgets.exe',
    'useroobebroker.exe', 'phoneexperiencehost.exe', 'crossdeviceservice.exe',
    'video.ui.exe', 'snippingtool.exe', 'systemsettings.exe',
    'igfxem.exe', 'syntpenh.exe', 'flow.exe', 'onedrive.sync.service.exe',
    'explorer.exe', 'code.exe', 'node.exe', 'python.exe', 'bash.exe',
    'spotify.exe', 'opera_crashreporter.exe', 'codesetup-stable*.exe',
    'codesetup-stable*.tmp', 'devsense.php.ls.exe'
}

def is_trusted_process(name, path):
    """Check if process is trusted by name or path"""
    if not name:
        return False
    
    name_lower = name.lower()
    
    if name_lower in TRUSTED_PROCESS_NAMES:
        return True
    
    if any(pattern in name_lower for pattern in ['codesetup', 'vscode', 'spotify', 'opera']):
        return True
    
    return is_whitelisted_path(path)

# ========== Multi-hash calculation ==========
def calculate_file_hashes(filepath, max_size=50*1024*1024):
    """
    Calculate multiple hashes of a file for comprehensive detection
    Returns: dict with sha256, md5, sha1, and file size
    """
    if not filepath or not os.path.isfile(filepath):
        return None
    
    try:
        file_size = os.path.getsize(filepath)
        
        # Skip very large files for performance
        if file_size > max_size:
            return {"size": file_size, "too_large": True}
        
        sha256_obj = hashlib.sha256()
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        
        with open(filepath, 'rb') as f:
            # Read file in chunks
            while chunk := f.read(8192):
                sha256_obj.update(chunk)
                md5_obj.update(chunk)
                sha1_obj.update(chunk)
        
        return {
            "sha256": sha256_obj.hexdigest(),
            "md5": md5_obj.hexdigest(),
            "sha1": sha1_obj.hexdigest(),
            "size": file_size
        }
    except Exception as e:
        print(f"Error hashing {filepath}: {e}")
        return None

def extract_script_from_cmdline(cmdline):
    if not cmdline or len(cmdline) < 2:
        return None
    for arg in cmdline[1:]:
        if arg.endswith(('.py', '.js', '.ps1', '.bat', '.vbs')):
            return arg
    return None
SUSPICIOUS_SCRIPT_PATTERNS = [
    "pynput",
    "keyboard",
    "GetAsyncKeyState",
    "win32api",
    "win32clipboard",
    "socket",
    "requests",
    "subprocess",
    "os.system",
    "cryptography",
    "base64",
    "keylog",
]

def scan_script_file(script_path):
    try:
        with open(script_path, "r", errors="ignore") as f:
            content = f.read()

        matches = []
        for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.lower() in content.lower():
                matches.append(pattern)

        return matches

    except Exception:
        return []

# ========== Enhanced malware detection ==========
def check_malware_comprehensive(filepath):
    """
    Comprehensive malware check using:
    1. Multi-hash comparison (SHA256, MD5, SHA1)
    2. File signature scanning
    3. Suspicious filename patterns
    4. File entropy analysis
    
    Returns: (is_malware, detection_info, file_hashes)
    """
    detection_info = {
        "hash_match": False,
        "signature_match": False,
        "suspicious_name": False,
        "high_entropy": False,
        "details": []
    }
    

    # Get file hashes
    hashes = calculate_file_hashes(filepath)
    if not hashes or hashes.get("too_large"):
        return False, detection_info, hashes
    
    # 1. CHECK MULTIPLE HASH TYPES
    for hash_type in ["sha256", "md5", "sha1"]:
        hash_value = hashes.get(hash_type)
        if hash_value and hash_value in malware_hashes.get(hash_type, {}):
            detection_info["hash_match"] = True
            malware_data = malware_hashes[hash_type][hash_value]
            detection_info["details"].append(f"Hash match ({hash_type.upper()}): {malware_data.get('name', 'Unknown')}")
            return True, detection_info, hashes
    
    # 2. CHECK SUSPICIOUS FILENAME PATTERNS
    filename = os.path.basename(filepath)
    for pattern in SUSPICIOUS_FILENAME_PATTERNS:
        if pattern.match(filename):
            detection_info["suspicious_name"] = True
            detection_info["details"].append(f"Suspicious filename pattern: {filename}")
            break
    
    # 3. SCAN FILE FOR MALICIOUS SIGNATURES
    try:
        with open(filepath, 'rb') as f:
            # Read first 1MB for signature scanning
            file_content = f.read(1024 * 1024)
            
            # Check for suspicious strings
            for sus_string in MALWARE_SIGNATURES["suspicious_strings"]:
                if sus_string in file_content:
                    detection_info["signature_match"] = True
                    detection_info["details"].append(f"Malicious string found: {sus_string.decode('utf-8', errors='ignore')}")
                    break
            
            # Check for packer signatures
            for packer in MALWARE_SIGNATURES["packer_signatures"]:
                if packer in file_content:
                    detection_info["details"].append(f"Packed executable detected: {packer.decode('utf-8', errors='ignore')}")
            
            # Check for suspicious APIs
            suspicious_api_count = 0
            for api in MALWARE_SIGNATURES["suspicious_apis"]:
                if api in file_content:
                    suspicious_api_count += 1
            
            if suspicious_api_count >= 3:  # Multiple suspicious APIs
                detection_info["signature_match"] = True
                detection_info["details"].append(f"Multiple suspicious APIs found ({suspicious_api_count})")
    
    except Exception as e:
        pass  # File might be in use or not readable
    
    # 4. CALCULATE ENTROPY (high entropy = potentially encrypted/packed)
    try:
        entropy = calculate_entropy(filepath)
        if entropy > 7.0:  # High entropy threshold
            detection_info["high_entropy"] = True
            detection_info["details"].append(f"High entropy ({entropy:.2f}) - possibly packed/encrypted")
    except:
        pass
    
    # Determine if malicious based on multiple indicators
    is_malware = (
        detection_info["hash_match"] or 
        detection_info["signature_match"] or
        (detection_info["suspicious_name"] and detection_info["high_entropy"])
    )
    
    return is_malware, detection_info, hashes

import math

def calculate_entropy(filepath, sample_size=65536):
    """Calculate true Shannon entropy (0–8)."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(sample_size)

        if not data:
            return 0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count == 0:
                continue
            p_x = count / data_len
            entropy -= p_x * math.log2(p_x)

        return entropy

    except Exception:
        return 0


# ========== File monitoring ==========
class FileEventHandler(FileSystemEventHandler):
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
    path_to_monitor = [
        os.path.expanduser("~/Documents"), 
        os.path.expanduser("~/Downloads"), 
        os.path.expanduser("~/Desktop")
    ] 
    for path in path_to_monitor:
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True)
    observer.daemon = True
    observer.start()
    return observer

# ========== Helper functions ==========
def get_dir(path):
    if not path:
        return None
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 1:
        return None
    return "/".join(parts[:-1])

def get_process_from_path(path):
    """Optimized: with timeout"""
    for p in psutil.process_iter(['pid', 'name']):
        try:
            for f in p.open_files():
                if f.path == path:
                    return p
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieException):
            continue
    return None

# ========== Main scanning logic (ENHANCED) ==========
def scan_processes(force_refresh=False):
    """
    Enhanced scan with multi-hash detection and signature scanning
    """
    global _scan_cache, file_activity_by_pid, file_activity_global
    
    current_time = time.time()
    if not force_refresh and _scan_cache["last_result"] is not None:
        time_since_last = current_time - _scan_cache["last_scan_time"]
        if time_since_last < _scan_cache["cache_duration"]:
            print(f"⚡ Using cached scan results ({time_since_last:.1f}s old)")
            return _scan_cache["last_result"]
    
    print("🔍 Starting enhanced multi-layer scan...")
    
    with lock:
        file_activity_by_pid_snapshot = dict(file_activity_by_pid)
        file_activity_global_snapshot = file_activity_global
        file_activity_by_pid = defaultdict(int)
        file_activity_global = 0
    
    processes = []
    process_objects = {}
    all_processes_count = 0
    
    # Batch CPU warmup
    print("   Warming up CPU measurements...")
    procs_to_monitor = []
    for p in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            all_processes_count += 1
            
            exe = p.info.get('exe')
            if not exe:
                continue
                
            exe_lower = exe.lower()
            
            if exe_lower in trusted_processes_paths:
                continue
            
            if is_whitelisted_path(exe):
                continue
                
            if is_trusted_process(p.info.get('name'), exe):
                continue
            
            p.cpu_percent(interval=0)
            procs_to_monitor.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    time.sleep(0.3)

    # Collect process info
    print(f"   Collecting data from {len(procs_to_monitor)} processes...")
    count = 0
    
    for p in procs_to_monitor:
        try:
            info = p.as_dict([
                'pid', 'name', 'exe', 'cmdline', 'cpu_percent', 
                'memory_info', 'num_threads'
            ])
            
            exe = info.get('exe')
            name = info.get('name')
            
            if is_trusted_process(name, exe):
                continue
            
            try:
                info['cpu_percent'] = p.cpu_percent(interval=0)
            except:
                info['cpu_percent'] = 0
            
            info['num_connections'] = 0
                
            processes.append(info)
            process_objects[info['pid']] = p
            count += 1
            
            if count % 50 == 0:
                print(f"   Processed {count} processes...")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    print(f"✓ Collected {len(processes)} processes after filtering (Total: {all_processes_count})")
    
    # Calculate directory frequency
    dirs = []
    for p in processes:
        d = get_dir(p.get("exe"))
        if d:
            dirs.append(d)

    dir_frequency = Counter(dirs)
    TOTAL = all_processes_count

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

    print("   Analyzing processes with multi-layer detection...")
    for idx, p in enumerate(processes):
        score = 0
        reasons = []
        malware_info = None
        detection_details = []
        file_hashes = None
        
        proc_obj = process_objects.get(p["pid"])
        exe_path = p.get("exe")
        name = p.get("name")

        if is_trusted_process(name, exe_path):
            continue
        #
        cmdline = p.get("cmdline")
        script_path = extract_script_from_cmdline(cmdline)

        if script_path and os.path.exists(script_path):
            matches = scan_script_file(script_path)
            if matches:
                score += 2
                reasons.append("suspicious_script_patterns")
                detection_details.extend(matches)

        
        # ===== ENHANCED MALWARE DETECTION =====
        is_malware, detection_info, file_hashes = check_malware_comprehensive(exe_path)
        
        if is_malware:
            if detection_info["hash_match"]:
                score += 10  # Confirmed malware by hash
                reasons.append("confirmed_malware_hash")
            elif detection_info["signature_match"]:
                score += 5  # Malicious signatures found
                reasons.append("malicious_signatures")
            
            if detection_info["suspicious_name"]:
                score += 2
                reasons.append("suspicious_filename")
            
            if detection_info["high_entropy"]:
                score += 1
                reasons.append("high_entropy_packed")
            
            detection_details = detection_info["details"]
            
            print(f"🚨 THREAT DETECTED: {name} - {', '.join(detection_details)}")

        # ===== BEHAVIORAL CHECKS =====
        
        if is_rare_path(exe_path):
            score += 0.5
            reasons.append("rare_execution_path")

        cpu = p.get("cpu_percent", 0)
        if cpu and cpu > 50:
            score += 1
            reasons.append("high_cpu")

        mem_info = p.get("memory_info")
        if mem_info and mem_info.rss > 500 * 1024 * 1024:
            score += 1
            reasons.append("high_memory")
        
        threads = p.get("num_threads", 0)
        if threads and threads > 100:
            score += 1
            reasons.append("high_threads")
        
        # Check connections only for suspicious processes
        if score >= 1:
            try:
                connections = len(proc_obj.net_connections()) if proc_obj else 0
                if connections > 100:
                    score += 1
                    reasons.append("high_connections")
            except:
                pass
        
        # Hidden executable
        if exe_path and os.path.isfile(exe_path):
            try:
                attrs = os.stat(exe_path).st_file_attributes
                if attrs & 0x2:
                    score += 2
                    reasons.append("hidden_executable")
            except AttributeError:
                pass
        
        # Rapid child creation
        if proc_obj and score >= 1:
            try:
                children = proc_obj.children()
                recent_children = [c for c in children if time.time() - c.create_time() < 60]
                if len(recent_children) > 15:
                    score += 1
                    reasons.append("rapid_child_creation")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Suspicious children
        if proc_obj and score >= 1:
            try:
                for c in proc_obj.children():
                    if c.name().lower() in ["cmd.exe", "powershell.exe"]:
                        score += 1
                        reasons.append("creating_suspicious_children")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # File activity
        activity_count = file_activity_by_pid_snapshot.get(p["pid"], 0)
        if activity_count > 50:
            score += 1
            reasons.append("high_file_activity")
        if file_activity_global_snapshot > 500:
            score += 1
            reasons.append("high_global_file_activity")

        # Determine severity
        if detection_info.get("hash_match"):
            severity = "confirmed_malware"
        elif is_malware:
            severity = "critical"
        elif score >= 5:
            severity = "critical"
        elif score >= 3.5:
            severity = "warning"
        else:
            severity = "info"

        entry = {
            "id": p["pid"],
            "pid": p["pid"],
            "name": name or "Unknown",
            "path": exe_path or "N/A",
            "score": score,
            "reasons": reasons,
            "severity": severity,
            "time": time.strftime("%H:%M:%S"),
            "status": "detected" if score >= 3.5 else "safe",
            "malware_info": detection_details if detection_details else None,
            "file_hash": file_hashes.get("sha256") if file_hashes else None,
            "hashes": file_hashes
        }

        if p["pid"] in seen_pids:
            continue
        seen_pids.add(p["pid"])

        if score >= 3.5:
            alerts.append(entry)
        else:
            safe.append(entry)
        
        if (idx + 1) % 100 == 0:
            print(f"   Analyzed {idx + 1}/{len(processes)} processes...")

    result = {
        "total_processes": TOTAL,
        "alerts": alerts,
        "safe": safe,
        "processes": processes
    }
    
    _scan_cache["last_scan_time"] = current_time
    _scan_cache["last_result"] = result
    
    print(f"✓ Enhanced scan complete: {len(alerts)} threats detected, {len(safe)} safe")
    
    return result

def stream_processes():
    """Stream ALL processes for accurate count and progress tracking"""
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
            time.sleep(0.02)
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
            cpu_percent = p.get('cpu_percent', 0)
            
            alert = next((a for a in scan_data['alerts'] if a['pid'] == p['pid']), None)
            
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
            
            if process_uuid:
                pid_to_uuid[p['pid']] = process_uuid
        
        print(f"✓ Logged {len(scan_data['processes'])} processes")
        
        alerts_logged = 0
        for alert in scan_data['alerts']:
            pid = alert['pid']
            process_uuid = pid_to_uuid.get(pid)
            
            if process_uuid:
                if alert['severity'] == 'confirmed_malware':
                    if alert.get('malware_info'):
                        title = f"🚨 CONFIRMED MALWARE: {', '.join(alert['malware_info'][:2])}"
                    else:
                        title = f"🚨 CONFIRMED MALWARE: {alert['name']}"
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
        
        print(f"✓ Logged {alerts_logged}/{len(scan_data['alerts'])} alerts")
        
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
        
        print(f"✓ Scan completed with risk level: {risk_level} (score: {risk_score})")
        return scan_id
        
    except Exception as e:
        print(f"✗ Error storing scan results: {e}")
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
    print("File monitoring started. Running scan...")
    result = scan_processes()
    print(f"\nTotal processes: {result['total_processes']}")
    print(f"Alerts: {len(result['alerts'])}")
    print(f"Safe: {len(result['safe'])}")
    if result['alerts']:
        print("\nAlerts:")
        for alert in result['alerts']:
            print(f"  - {alert['name']} (PID {alert['pid']}): score={alert['score']}, reasons={alert['reasons']}")
    
    print("\nMonitoring files... Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()