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
import pefile
import tlsh
import numpy as np
from ml_model import PEAnalysisMLModel

db = Database()

file_activity_by_pid = defaultdict(int)
file_activity_global = 0
lock = threading.Lock()

_scan_cache = {
    "last_scan_time": 0,
    "last_result": None,
    "cache_duration": 5
}

# Initialize ML Model
print("Initializing PE Analysis ML Model...")
ml_model = PEAnalysisMLModel()
if ml_model.is_trained:
    print("ML Model loaded and ready")
else:
    print("WARNING: ML Model not trained. Run 'python ml_model.py' to train first.")
print()

# Hash databases
malware_hashes = {
    "sha256": {},
    "md5": {},
    "sha1": {},
    "imphash": {},
    "tlsh": {}
}

# REFINED malware patterns - more specific to avoid false positives
malware_patterns = {
    "wannacry": {
        "imphash": [],
        "strings": [b"@WanaDecryptor@", b".WNCRYT", b".WNCRY", b"tasksche.exe"],
        "apis": [b"CryptEncrypt", b"CryptAcquireContext"],
        "entropy_range": (6.8, 7.8),
        "file_size_range": (100000, 5000000),
        "tlsh_patterns": [],
        "min_string_matches": 1,
        "min_api_matches": 2
    },
    "emotet": {
        "imphash": [],
        "strings": [b"\x00emotet\x00", b"e-f@!$emotet"],
        "apis": [b"URLDownloadToFile", b"CreateProcess"],
        "entropy_range": (6.2, 7.5),
        "file_size_range": (200000, 2000000),
        "tlsh_patterns": [],
        "min_string_matches": 1,
        "min_api_matches": 2
    },
    "cobaltstrike": {
        "imphash": [],
        "strings": [b"ReflectiveLoader", b"beacon.dll", b"\x00%c%c%c%c%c%c%c%c%cMSSE-"],
        "apis": [b"VirtualAllocEx", b"CreateRemoteThread"],
        "entropy_range": (6.8, 7.9),
        "file_size_range": (50000, 2000000),
        "tlsh_patterns": [],
        "min_string_matches": 1,
        "min_api_matches": 2
    },
    "mimikatz": {
        "imphash": [],
        "strings": [b"gentilkiwi", b"sekurlsa::logonpasswords", b"lsadump::sam"],
        "apis": [b"LsaCallAuthenticationPackage", b"SamEnumerateUsersInDomain"],
        "entropy_range": (5.8, 7.0),
        "file_size_range": (100000, 1500000),
        "tlsh_patterns": [],
        "min_string_matches": 1,
        "min_api_matches": 1
    }
}

def load_malware_hashes():
    """Load malware hashes from JSON file"""
    global malware_hashes
    
    for json_file in ["malware_hashes_comprehensive.json", "malware_hashes.json"]:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                if '_metadata' in data:
                    metadata = data.pop('_metadata')
                    print(f"Database metadata: {metadata.get('total_entries', 0)} entries")
                
                data.pop('README', None)
                data.pop('INFO', None)
                
                malware_hashes["sha256"] = data
                print(f"Loaded {len(data)} SHA256 malware signatures from {json_file}")
                
                load_imphash_database()
                load_tlsh_database()
                return
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
    
    print(f"Warning: No malware hash database found")

def load_imphash_database():
    """Load import hash database"""
    imphash_files = ["malware_imphashes.json", "imphash_db.json"]
    for json_file in imphash_files:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    malware_hashes["imphash"] = data
                    
                    for hash_value, info in data.items():
                        family = info.get('family', '').lower()
                        if family in malware_patterns:
                            malware_patterns[family]['imphash'].append(hash_value)
                    
                print(f"Loaded {len(malware_hashes['imphash'])} IMPHASH signatures")
                break
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

def load_tlsh_database():
    """Load TLSH fuzzy hash database"""
    tlsh_files = ["malware_tlsh.json", "tlsh_db.json"]
    for json_file in tlsh_files:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    malware_hashes["tlsh"] = data
                    
                    for hash_value, info in data.items():
                        family = info.get('family', '').lower()
                        if family in malware_patterns:
                            malware_patterns[family]['tlsh_patterns'].append(hash_value)
                    
                print(f"Loaded {len(malware_hashes['tlsh'])} TLSH fuzzy signatures")
                break
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

load_malware_hashes()

# REFINED suspicious signatures - more specific
MALWARE_SIGNATURES = {
    "suspicious_strings": [
        b"\\\\ADMIN$\\\\system32", b"HKTL_", b"Meterpreter",
        b"\\x00mimikatz\\x00", b"\\x00cryptolocker\\x00"
    ],
    "packer_signatures": [
        b"UPX!", b"MPRESS", b"Themida", b"VMProtect"
    ]
}

# More specific suspicious filename patterns
SUSPICIOUS_FILENAMES = [
    r"^(invoice|document|report|photo|video|order|payment|receipt)\.(exe|scr|pif)$",
    r"^(crack|keygen|patch|activator).*\.(exe|scr)$",
    r".*\.(exe|scr|pif)\.exe$"  # Double extension
]

SUSPICIOUS_FILENAME_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_FILENAMES]

def get_trusted_paths():
    """Get trusted system paths"""
    trusted = set()
    system = platform.system()
    
    if system == "Windows":
        windir = os.environ.get('WINDIR', 'C:\\Windows')
        progfiles = os.environ.get('ProgramFiles', 'C:\\Program Files')
        progfiles_x86 = os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')
        
        # Core Windows processes - full paths only
        core_processes = [
            os.path.join(windir, "explorer.exe"),
            os.path.join(windir, "System32", "svchost.exe"),
            os.path.join(windir, "System32", "lsass.exe"),
            os.path.join(windir, "System32", "csrss.exe"),
            os.path.join(windir, "System32", "services.exe"),
            os.path.join(windir, "System32", "wininit.exe"),
        ]
        
        for proc in core_processes:
            trusted.add(proc.lower())
    
    return trusted

trusted_processes_paths = get_trusted_paths()

# Whitelisted directory patterns
WHITELISTED_PATTERNS = [
    r'C:\\Windows\\System32', r'C:\\Windows\\SystemApps', 
    r'C:\\Program Files\\WindowsApps', r'C:\\Program Files\\Microsoft',
    r'C:\\Program Files\\Common Files\\microsoft shared',
    r'C:\\Windows\\WinSxS'
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
    'appvshnotify.exe', 'officeclicktorun.exe'
}

def is_trusted_process(name, path):
    """Check if process is trusted"""
    if not name:
        return False
    
    name_lower = name.lower()
    
    if name_lower in TRUSTED_PROCESS_NAMES:
        return True
    
    return is_whitelisted_path(path)

def calculate_tlsh_hash(filepath):
    """Calculate TLSH fuzzy hash"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if len(data) < 50:
            return None
            
        return tlsh.hash(data)
    except:
        return None

def check_tlsh_similarity(filepath):
    """Check TLSH similarity with threshold of 80%"""
    file_hash = calculate_tlsh_hash(filepath)
    if not file_hash:
        return False, None, 0
    
    best_match = None
    best_similarity = 0
    
    for known_hash, malware_info in malware_hashes.get("tlsh", {}).items():
        try:
            diff = tlsh.diff(file_hash, known_hash)
            similarity = max(0, 100 - (diff / 10))
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = malware_info
        except:
            continue
    
    # Only return positive if similarity is very high (80%+)
    if best_similarity >= 80:
        return True, best_match, best_similarity
    
    return False, None, best_similarity

def calculate_imphash(filepath):
    """Calculate import hash"""
    try:
        pe = pefile.PE(filepath)
        return pe.get_imphash()
    except:
        return None

def check_imphash(filepath):
    """Check import hash match"""
    imphash = calculate_imphash(filepath)
    if not imphash:
        return False, None
    
    if imphash in malware_hashes.get("imphash", {}):
        return True, malware_hashes["imphash"][imphash]
    
    for malware_name, pattern in malware_patterns.items():
        if imphash in pattern.get("imphash", []):
            return True, {"name": malware_name, "family": malware_name}
    
    return False, None

def check_pattern_match(filepath, file_content=None):
    """Check pattern match with stricter requirements"""
    if file_content is None:
        try:
            with open(filepath, 'rb') as f:
                file_content = f.read(1024 * 1024)
        except:
            return False, None, 0
    
    entropy = calculate_entropy(filepath)
    file_size = os.path.getsize(filepath)
    best_match = None
    best_score = 0
    
    for malware_name, pattern in malware_patterns.items():
        score = 0
        string_matches = 0
        api_matches = 0
        
        # Count string matches
        for string in pattern.get("strings", []):
            if string in file_content:
                string_matches += 1
        
        # Count API matches
        for api in pattern.get("apis", []):
            if api in file_content:
                api_matches += 1
        
        # Check if minimum thresholds are met
        min_strings = pattern.get("min_string_matches", 1)
        min_apis = pattern.get("min_api_matches", 2)
        
        if string_matches < min_strings and api_matches < min_apis:
            continue
        
        # Calculate score only if thresholds met
        if string_matches >= min_strings:
            score += 40
        
        if api_matches >= min_apis:
            score += 40
        elif api_matches >= 1:
            score += 20
        
        # Entropy check
        entropy_range = pattern.get("entropy_range")
        if entropy_range and entropy_range[0] <= entropy <= entropy_range[1]:
            score += 10
        
        # Size check
        size_range = pattern.get("file_size_range")
        if size_range and size_range[0] <= file_size <= size_range[1]:
            score += 10
        
        if score > best_score:
            best_score = score
            best_match = malware_name
    
    # Higher threshold for pattern match (70% instead of 50%)
    if best_score >= 70:
        return True, best_match, best_score
    
    return False, None, best_score

def calculate_entropy(filepath, sample_size=65536):
    """Calculate Shannon entropy"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(sample_size)
        
        if not data:
            return 0
        
        from collections import Counter
        import math
        
        counter = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in counter.values():
            freq = count / data_len
            entropy -= freq * math.log2(freq)
        
        return entropy
    except:
        return 0

def calculate_file_hashes(filepath, max_size=50*1024*1024):
    """Calculate file hashes"""
    if not filepath or not os.path.isfile(filepath):
        return None
    
    try:
        file_size = os.path.getsize(filepath)
        
        if file_size > max_size:
            return {"size": file_size, "too_large": True}
        
        sha256_obj = hashlib.sha256()
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        
        with open(filepath, 'rb') as f:
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
        return None

def check_malware_comprehensive(filepath):
    """
    Streamlined malware check with focus on accuracy
    Priority: Hash > ML > TLSH > Imphash > Pattern
    """
    detection_info = {
        "hash_match": False,
        "fuzzy_match": False,
        "fuzzy_similarity": 0,
        "imphash_match": False,
        "pattern_match": False,
        "pattern_confidence": 0,
        "ml_match": False,
        "ml_confidence": 0,
        "signature_match": False,
        "suspicious_name": False,
        "high_entropy": False,
        "details": [],
        "confidence": 0,
        "matched_family": None
    }
    
    hashes = calculate_file_hashes(filepath)
    if not hashes or hashes.get("too_large"):
        return False, detection_info, hashes
    
    confidence = 0
    
    # 1. EXACT HASH MATCH - Highest priority
    for hash_type in ["sha256", "md5", "sha1"]:
        hash_value = hashes.get(hash_type)
        if hash_value and hash_value in malware_hashes.get(hash_type, {}):
            detection_info["hash_match"] = True
            malware_data = malware_hashes[hash_type][hash_value]
            name = malware_data.get('name', 'Unknown')
            family = malware_data.get('family', name)
            detection_info["details"].append(f"EXACT HASH MATCH: {name}")
            detection_info["matched_family"] = family
            confidence = 100
            detection_info["confidence"] = confidence
            return True, detection_info, hashes
    
    # 2. MACHINE LEARNING - High priority
    if ml_model.is_trained:
        ml_match, ml_confidence, _ = ml_model.predict(filepath)
        if ml_match and ml_confidence >= 0.85:  # High confidence threshold
            detection_info["ml_match"] = True
            detection_info["ml_confidence"] = ml_confidence
            detection_info["details"].append(f"ML DETECTION: {ml_confidence:.1%} confidence")
            confidence += ml_confidence * 100
    
    # 3. TLSH FUZZY HASH - 80%+ similarity required
    tlsh_result, tlsh_info, tlsh_similarity = check_tlsh_similarity(filepath)
    if tlsh_result:
        detection_info["fuzzy_match"] = True
        detection_info["fuzzy_similarity"] = tlsh_similarity
        name = tlsh_info.get('name', 'Unknown') if tlsh_info else 'Unknown'
        family = tlsh_info.get('family', name) if tlsh_info else 'Unknown'
        detection_info["details"].append(f"TLSH FUZZY MATCH: {tlsh_similarity:.1f}% similar to {name}")
        detection_info["matched_family"] = family
        confidence += tlsh_similarity
    
    # 4. IMPORT HASH
    imphash_match, imphash_info = check_imphash(filepath)
    if imphash_match:
        detection_info["imphash_match"] = True
        name = imphash_info.get('name', 'Unknown')
        family = imphash_info.get('family', name)
        detection_info["details"].append(f"IMPORT HASH MATCH: {name}")
        detection_info["matched_family"] = family
        confidence += 85
    
    # 5. PATTERN MATCH - Stricter requirements
    try:
        with open(filepath, 'rb') as f:
            file_content = f.read(1024 * 1024)
    except:
        file_content = None
    
    if file_content:
        pattern_match, pattern_name, pattern_score = check_pattern_match(filepath, file_content)
        if pattern_match:
            detection_info["pattern_match"] = True
            detection_info["pattern_confidence"] = pattern_score
            detection_info["details"].append(f"PATTERN MATCH: {pattern_name} ({pattern_score}%)")
            detection_info["matched_family"] = pattern_name
            confidence += pattern_score
    
    # 6. SUSPICIOUS FILENAME - Lower weight
    filename = os.path.basename(filepath)
    for pattern in SUSPICIOUS_FILENAME_PATTERNS:
        if pattern.match(filename):
            detection_info["suspicious_name"] = True
            detection_info["details"].append(f"Suspicious filename: {filename}")
            confidence += 15
            break
    
    # 7. HIGH ENTROPY - Only very high entropy (7.5+)
    try:
        entropy = calculate_entropy(filepath)
        if entropy > 7.5:
            detection_info["high_entropy"] = True
            detection_info["details"].append(f"Very high entropy ({entropy:.2f}) - likely packed")
            confidence += 10
    except:
        pass
    
    detection_info["confidence"] = min(confidence, 100)
    
    # FINAL DECISION - Stricter criteria
    is_malware = (
        detection_info["hash_match"] or
        (detection_info["ml_match"] and detection_info["ml_confidence"] >= 0.85) or
        detection_info["fuzzy_match"] or
        detection_info["imphash_match"] or
        detection_info["pattern_match"] or
        confidence >= 75  # Higher threshold
    )
    
    return is_malware, detection_info, hashes

# File monitoring
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

def get_process_from_path(path):
    for p in psutil.process_iter(['pid', 'name']):
        try:
            for f in p.open_files():
                if f.path == path:
                    return p
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieException):
            continue
    return None

def scan_processes(force_refresh=False):
    """Optimized scanning function"""
    global _scan_cache, file_activity_by_pid, file_activity_global
    
    current_time = time.time()
    if not force_refresh and _scan_cache["last_result"] is not None:
        time_since_last = current_time - _scan_cache["last_scan_time"]
        if time_since_last < _scan_cache["cache_duration"]:
            print(f"Using cached scan results ({time_since_last:.1f}s old)")
            return _scan_cache["last_result"]
    
    print("Starting enhanced malware scan...")
    
    with lock:
        file_activity_by_pid_snapshot = dict(file_activity_by_pid)
        file_activity_global_snapshot = file_activity_global
        file_activity_by_pid = defaultdict(int)
        file_activity_global = 0
    
    processes = []
    process_objects = {}
    all_processes_count = 0
    
    # Quick CPU measurement
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
    
    time.sleep(0.1)  # Reduced sleep time

    print(f"Collecting data from {len(procs_to_monitor)} processes...")
    
    for p in procs_to_monitor:
        try:
            info = p.as_dict([
                'pid', 'name', 'exe', 'cpu_percent', 
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
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    print(f"Collected {len(processes)} processes after filtering (Total: {all_processes_count})")
    
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
        return dir_frequency[d] / len(processes) < 0.03

    alerts = []
    safe = []
    seen_pids = set()

    print("Analyzing processes...")
    for p in processes:
        score = 0
        reasons = []
        detection_details = []
        file_hashes = None
        detection_confidence = 0
        
        proc_obj = process_objects.get(p["pid"])
        exe_path = p.get("exe")
        name = p.get("name")

        if is_trusted_process(name, exe_path):
            continue

        is_malware, detection_info, file_hashes = check_malware_comprehensive(exe_path)
        
        if is_malware:
            detection_confidence = detection_info.get("confidence", 0)
            
            if detection_info["hash_match"]:
                score += 10
                reasons.append("confirmed_malware_hash")
            if detection_info["fuzzy_match"]:
                score += 8
                reasons.append(f"fuzzy_match_{detection_info['fuzzy_similarity']:.0f}pct")
            if detection_info["imphash_match"]:
                score += 7
                reasons.append("import_hash_match")
            if detection_info["pattern_match"]:
                score += 6
                reasons.append("malware_pattern")
            if detection_info["ml_match"]:
                score += 5
                reasons.append("ml_detection")
            if detection_info["suspicious_name"]:
                score += 2
                reasons.append("suspicious_filename")
            if detection_info["high_entropy"]:
                score += 1
                reasons.append("high_entropy")
            
            detection_details = detection_info["details"]
            
            if detection_info.get("matched_family"):
                print(f"THREAT DETECTED: {name} - {detection_info['matched_family']} family (confidence: {detection_confidence}%)")
                reasons.append(f"family:{detection_info['matched_family']}")
            else:
                print(f"THREAT DETECTED: {name} - Confidence: {detection_confidence}%")

        # Behavioral checks - only for processes with some suspicion
        if score > 0:
            if is_rare_path(exe_path):
                score += 0.3
                reasons.append("rare_path")

            cpu = p.get("cpu_percent", 0)
            if cpu and cpu > 70:
                score += 0.5
                reasons.append("high_cpu")

            mem_info = p.get("memory_info")
            if mem_info and mem_info.rss > 1000 * 1024 * 1024:  # 1GB
                score += 0.5
                reasons.append("high_memory")

        # Determine severity - stricter thresholds
        if detection_info.get("hash_match"):
            severity = "confirmed_malware"
        elif detection_confidence >= 85:
            severity = "confirmed_malware"
        elif detection_confidence >= 70 or score >= 8:
            severity = "critical"
        elif detection_confidence >= 50 or score >= 5:
            severity = "warning"
        elif detection_confidence >= 30 or score >= 3:
            severity = "suspicious"
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
            "status": "detected" if severity in ["confirmed_malware", "critical", "warning", "suspicious"] else "safe",
            "malware_info": detection_details if detection_details else None,
            "file_hash": file_hashes.get("sha256") if file_hashes else None,
            "hashes": file_hashes,
            "detection_confidence": detection_confidence,
            "matched_family": detection_info.get("matched_family")
        }
        
        if p["pid"] in seen_pids:
            continue
        seen_pids.add(p["pid"])

        if severity in ["confirmed_malware", "critical", "warning", "suspicious"]:
            alerts.append(entry)
        else:
            safe.append(entry)

    result = {
        "total_processes": all_processes_count,
        "alerts": alerts,
        "safe": safe,
        "processes": processes
    }
    
    _scan_cache["last_scan_time"] = current_time
    _scan_cache["last_result"] = result
    
    confirmed = len([a for a in alerts if a['severity'] == 'confirmed_malware'])
    critical = len([a for a in alerts if a['severity'] == 'critical'])
    warning = len([a for a in alerts if a['severity'] == 'warning'])
    suspicious = len([a for a in alerts if a['severity'] == 'suspicious'])
    
    print(f"Scan complete: {confirmed} confirmed, {critical} critical, {warning} warning, {suspicious} suspicious")
    
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
            time.sleep(0.01)
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
        
        print(f"Logged {len(scan_data['processes'])} processes")
        
        alerts_logged = 0
        for alert in scan_data['alerts']:
            pid = alert['pid']
            process_uuid = pid_to_uuid.get(pid)
            
            if process_uuid:
                if alert['severity'] == 'confirmed_malware':
                    if alert.get('matched_family'):
                        title = f"CONFIRMED MALWARE: {alert['matched_family']} family"
                    else:
                        title = f"CONFIRMED MALWARE: {alert['name']}"
                else:
                    confidence = alert.get('detection_confidence', 0)
                    title = f"{alert['severity'].upper()}: {alert['name']} (confidence: {confidence}%)"
                
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
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Malware Scanner')
    parser.add_argument('--scan', action='store_true', help='Run scan')
    
    args = parser.parse_args()
    
    if not ml_model.is_trained:
        print("\nWARNING: ML model not trained!")
        print("Run 'python ml_model.py' first to train the model")
        print("The scanner will still work using other detection methods.\n")
    
    observer = start_file_monitoring()
    print("=" * 60)
    print("ENHANCED MALWARE SCANNER")
    print("=" * 60)
    print(f"Loaded {len(malware_hashes['sha256'])} SHA256 signatures")
    print(f"Loaded {len(malware_hashes.get('imphash', {}))} IMPHASH signatures")
    print(f"Loaded {len(malware_hashes.get('tlsh', {}))} TLSH fuzzy signatures")
    print(f"ML Model: {'READY' if ml_model.is_trained else 'NOT TRAINED'}")
    print("=" * 60)
    
    print("Running scan...")
    result = scan_processes()
    print(f"\nScan Summary:")
    print(f"Total processes: {result['total_processes']}")
    print(f"Total alerts: {len(result['alerts'])}")
    print(f"Safe processes: {len(result['safe'])}")
    
    if result['alerts']:
        print("\nALERTS:")
        for alert in result['alerts']:
            confidence = alert.get('detection_confidence', 0)
            family = alert.get('matched_family', '')
            
            if family:
                print(f"[{alert['severity'].upper()}] {alert['name']} (PID {alert['pid']})")
                print(f"     Family: {family}")
                print(f"     Confidence: {confidence}%")
            else:
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