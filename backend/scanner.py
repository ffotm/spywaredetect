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

# ========== Cache to prevent duplicate scans ==========
_scan_cache = {
    "last_scan_time": 0,
    "last_result": None,
    "cache_duration": 5
}

# ========== Initialize ML Model ==========
print(" Initializing PE Analysis ML Model...")
ml_model = PEAnalysisMLModel()
if ml_model.is_trained:
    print("✓ ML Model loaded and ready")
else:
    print("⚠ ML Model not trained. Run 'python ml_model.py' to train first.")
print()

# ========== Multi-hash malware database ==========
malware_hashes = {
    "sha256": {},
    "md5": {},
    "sha1": {},
    "imphash": {},  # Import hash for PE files
    "tlsh": {}      # TLSH fuzzy hashes
}

# ========== Malware patterns database ==========
malware_patterns = {
    "wannacry": {
        "imphash": [],
        "strings": [b"wcry", b"wncry", b"@WanaDecryptor", b"WNCRY", b"WANNACRY"],
        "apis": [b"CryptEncrypt", b"InternetOpen", b"CreateService", b"StartService"],
        "entropy_range": (6.5, 7.8),
        "file_size_range": (100000, 5000000),
        "tlsh_patterns": []
    },
    "emotet": {
        "imphash": [],
        "strings": [b"emotet", b"e-f@!$", b"vmtoolsd", b"VBox"],
        "apis": [b"URLDownloadToFile", b"CreateProcess", b"GetProcAddress", b"VirtualAlloc"],
        "entropy_range": (6.2, 7.5),
        "file_size_range": (200000, 2000000),
        "tlsh_patterns": []
    },
    "cobaltstrike": {
        "imphash": [],
        "strings": [b"cobalt strike", b"beacon", b"sleep_mask", b"aggressor"],
        "apis": [b"VirtualAllocEx", b"CreateRemoteThread", b"SetWindowsHookEx", b"GetModuleHandle"],
        "entropy_range": (6.8, 7.9),
        "file_size_range": (50000, 2000000),
        "tlsh_patterns": []
    },
    "mimikatz": {
        "imphash": [],
        "strings": [b"mimikatz", b"sekurlsa", b"logonpasswords", b"kerberos", b"lsadump"],
        "apis": [b"OpenProcess", b"DuplicateToken", b"ImpersonateLoggedOnUser", b"LsaCallAuthenticationPackage"],
        "entropy_range": (5.8, 7.0),
        "file_size_range": (100000, 1000000),
        "tlsh_patterns": []
    },
    "lokibot": {
        "imphash": [],
        "strings": [b"Loki", b"Bot", b"PASSWORD", b"CREDITCARD"],
        "apis": [b"InternetReadFile", b"RegQueryValueEx", b"FindFirstFile"],
        "entropy_range": (6.0, 7.5),
        "file_size_range": (150000, 800000),
        "tlsh_patterns": []
    },
    "azorult": {
        "imphash": [],
        "strings": [b"AZORult", b"Stealer", b"BTC", b"Wallet"],
        "apis": [b"URLDownloadToFile", b"RegOpenKeyEx", b"CryptAcquireContext"],
        "entropy_range": (6.3, 7.6),
        "file_size_range": (100000, 600000),
        "tlsh_patterns": []
    }
}

def load_malware_hashes():
    """Load malware hashes from JSON file and build multiple hash indexes"""
    global malware_hashes
    
    for json_file in ["malware_hashes_comprehensive.json", "malware_hashes.json"]:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                # Remove metadata
                if '_metadata' in data:
                    metadata = data.pop('_metadata')
                    print(f"📊 Database metadata: {metadata.get('total_entries', 0)} entries")
                
                data.pop('README', None)
                data.pop('INFO', None)
                
                # Build SHA256 index
                malware_hashes["sha256"] = data
                
                print(f"✓ Loaded {len(data)} SHA256 malware signatures from {json_file}")
                
                # Try to load additional hash databases
                load_imphash_database()
                load_tlsh_database()
                
                return
            except Exception as e:
                print(f"✗ Error loading {json_file}: {e}")
    
    print(f"⚠ Warning: No malware hash database found")

def load_imphash_database():
    """Load import hash database"""
    imphash_files = ["malware_imphashes.json", "imphash_db.json"]
    for json_file in imphash_files:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    malware_hashes["imphash"] = data
                    
                    # Update pattern database with imphashes
                    for hash_value, info in data.items():
                        family = info.get('family', '').lower()
                        if family in malware_patterns:
                            malware_patterns[family]['imphash'].append(hash_value)
                    
                print(f"✓ Loaded {len(malware_hashes['imphash'])} IMPHASH signatures")
                break
            except Exception as e:
                print(f"✗ Error loading {json_file}: {e}")

def load_tlsh_database():
    """Load TLSH fuzzy hash database"""
    tlsh_files = ["malware_tlsh.json", "tlsh_db.json"]
    for json_file in tlsh_files:
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    malware_hashes["tlsh"] = data
                    
                    # Update pattern database with TLSH patterns
                    for hash_value, info in data.items():
                        family = info.get('family', '').lower()
                        if family in malware_patterns:
                            malware_patterns[family]['tlsh_patterns'].append(hash_value)
                    
                print(f"✓ Loaded {len(malware_hashes['tlsh'])} TLSH fuzzy signatures")
                break
            except Exception as e:
                print(f"✗ Error loading {json_file}: {e}")

load_malware_hashes()

# ========== YARA-like signature patterns ==========
MALWARE_SIGNATURES = {
    "suspicious_strings": [
        b"keylogger", b"ransomware", b"cryptolocker", b"mimikatz", b"metasploit",
        b"cobalt strike", b"empire", b"powershell empire", b"invoke-mimikatz",
        b"invoke-shellcode", b"get-credential", b"lsadump", b"procdump", b"sekurlsa",
        b"backdoor", b"rootkit", b"payload", b"exploit", b"shellcode", b"password",
        b"stealer", b"worm", b"dropper"
    ],
    "packer_signatures": [
        b"UPX", b"MPRESS", b"PECompact", b"ASPack", b"Themida", b"VMProtect", b"Enigma", b"Armadillo"
    ],
    "suspicious_apis": [
        b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"SetWindowsHookEx",
        b"GetAsyncKeyState", b"CryptEncrypt", b"RegSetValueEx", b"URLDownloadToFile",
        b"WinExec", b"ShellExecute", b"OpenProcess", b"DuplicateToken", b"ImpersonateLoggedOnUser",
        b"CreateProcess", b"InternetOpen", b"InternetReadFile"
    ]
}

# ========== Suspicious file name patterns ==========
SUSPICIOUS_FILENAMES = [
    r".*\.(exe|scr|pif|com|bat|cmd|vbs|js|jar|wsf)\.exe$",
    r"^(invoice|document|report|photo|video|order|payment|receipt|shipping)\.(exe|scr|pif)$",
    r"^(setup|install|crack|keygen|patch|activator).*\.(exe|scr|pif)$",
    r"^(chrome|firefox|edge|flash|java|adobe).*update.*\.(exe|scr|pif)$",
    r".*codec.*\.(exe|scr|pif)$",
    r".*player.*update.*\.(exe|scr|pif)$",
    r".*\.(vbs|ps1|bat|cmd)$",
    r".*\.(docm|xlsm|pptm)$",
    r".*password.*\.(exe|scr|pif)$",
    r".*bank.*\.(exe|scr|pif)$"
]

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
        trusted.add(os.path.join(windir, "System32", "taskhostw.exe").lower())
        
        # Common legitimate apps
        common_apps = [
            os.path.join(progfiles, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(progfiles_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(appdata, "Programs", "Microsoft VS Code", "Code.exe"),
            os.path.join(progfiles, "Microsoft Office", "root", "Office16", "WINWORD.EXE"),
            os.path.join(progfiles, "Microsoft Office", "root", "Office16", "EXCEL.EXE"),
        ]
        
        for app in common_apps:
            if os.path.exists(app):
                trusted.add(app.lower())
    
    elif system == "Linux":
        trusted.update([
            "/usr/bin/systemd", "/usr/bin/bash", "/usr/bin/python3",
            "/usr/bin/gnome-shell", "/usr/bin/Xorg"
        ])
    
    return trusted

trusted_processes_paths = get_trusted_paths()

# ========== Whitelisted patterns ==========
WHITELISTED_PATTERNS = [
    r'C:\\Windows\\System32', r'C:\\Windows\\SystemApps', r'C:\\Windows\\ImmersiveControlPanel',
    r'C:\\Program Files\\WindowsApps', r'C:\\Program Files\\Microsoft OneDrive',
    r'C:\\Program Files\\CONEXANT', r'C:\\Program Files\\Synaptics', r'Microsoft VS Code',
    r'\\Git\\', r'\\nodejs\\', r'\\Python\\', r'\\.vscode\\extensions',
    r'SpotifyAB\\.SpotifyMusic', r'Opera GX', r'WOMic', r'Discord', r'Slack', r'Teams'
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
    'video.ui.exe', 'snippingtool.exe', 'systemsettings.exe', 'igfxem.exe',
    'syntpenh.exe', 'flow.exe', 'onedrive.sync.service.exe', 'explorer.exe',
    'code.exe', 'node.exe', 'python.exe', 'bash.exe', 'spotify.exe',
    'opera_crashreporter.exe', 'discord.exe', 'slack.exe', 'teams.exe',
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'
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

# ========== TLSH Fuzzy Hashing Functions ==========
def calculate_tlsh_hash(filepath):
    """Calculate TLSH fuzzy hash for similarity matching"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if len(data) < 50:
            return None
            
        return tlsh.hash(data)
    except Exception as e:
        return None

def check_tlsh_similarity(filepath):
    """Check if file is similar to known malware using TLSH"""
    file_hash = calculate_tlsh_hash(filepath)
    if not file_hash:
        return False, None, 0
    
    best_match = None
    best_similarity = 0
    
    # Check against known TLSH hashes
    for known_hash, malware_info in malware_hashes.get("tlsh", {}).items():
        try:
            diff = tlsh.diff(file_hash, known_hash)
            similarity = max(0, 100 - (diff / 10))
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = malware_info
        except:
            continue
    
    # Check against pattern database
    for malware_name, pattern in malware_patterns.items():
        for pattern_hash in pattern.get("tlsh_patterns", []):
            try:
                diff = tlsh.diff(file_hash, pattern_hash)
                similarity = max(0, 100 - (diff / 10))
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = {"name": malware_name, "family": malware_name}
            except:
                continue
    
    if best_similarity > 70:
        return True, best_match, best_similarity
    elif best_similarity > 50:
        return "possible", best_match, best_similarity
    
    return False, None, best_similarity

def calculate_imphash(filepath):
    """Calculate import hash for PE files"""
    try:
        pe = pefile.PE(filepath)
        return pe.get_imphash()
    except Exception as e:
        return None

def check_imphash(filepath):
    """Check if file has same imports as known malware"""
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
    """Check if file matches known malware patterns"""
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
        
        # Check strings (40% weight)
        for string in pattern.get("strings", []):
            if string in file_content:
                score += 40
                break
        
        # Check APIs (30% weight)
        api_matches = 0
        for api in pattern.get("apis", []):
            if api in file_content:
                api_matches += 1
        if api_matches >= 3:
            score += 30
        elif api_matches >= 1:
            score += 15
        
        # Check entropy range (20% weight)
        entropy_range = pattern.get("entropy_range")
        if entropy_range and entropy_range[0] <= entropy <= entropy_range[1]:
            score += 20
        
        # Check file size range (10% weight)
        size_range = pattern.get("file_size_range")
        if size_range and size_range[0] <= file_size <= size_range[1]:
            score += 10
        
        if score > best_score:
            best_score = score
            best_match = malware_name
    
    if best_score >= 50:
        return True, best_match, best_score
    elif best_score >= 30:
        return "possible", best_match, best_score
    
    return False, None, best_score

def calculate_entropy(filepath, sample_size=65536):
    """Calculate Shannon entropy of file"""
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
    """Calculate multiple hashes of a file"""
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
        print(f"Error hashing {filepath}: {e}")
        return None

def check_malware_comprehensive(filepath):
    """
    Comprehensive malware check using multiple detection methods including ML
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
    file_content = None
    
    # 1. EXACT HASH MATCH
    for hash_type in ["sha256", "md5", "sha1"]:
        hash_value = hashes.get(hash_type)
        if hash_value and hash_value in malware_hashes.get(hash_type, {}):
            detection_info["hash_match"] = True
            malware_data = malware_hashes[hash_type][hash_value]
            name = malware_data.get('name', 'Unknown')
            family = malware_data.get('family', name)
            detection_info["details"].append(f"🚨 EXACT HASH MATCH: {name}")
            detection_info["matched_family"] = family
            confidence += 100
    
    # 2. TLSH FUZZY HASH
    tlsh_result, tlsh_info, tlsh_similarity = check_tlsh_similarity(filepath)
    if tlsh_result == True:
        detection_info["fuzzy_match"] = True
        detection_info["fuzzy_similarity"] = tlsh_similarity
        name = tlsh_info.get('name', 'Unknown') if tlsh_info else 'Unknown'
        family = tlsh_info.get('family', name) if tlsh_info else 'Unknown'
        detection_info["details"].append(f"🎯 TLSH FUZZY MATCH: {tlsh_similarity:.1f}% similar to {name}")
        detection_info["matched_family"] = family
        confidence += tlsh_similarity
    elif tlsh_result == "possible":
        detection_info["details"].append(f"🔍 Possible TLSH match: {tlsh_similarity:.1f}% similarity")
        confidence += tlsh_similarity * 0.5
    
    # 3. IMPORT HASH
    imphash_match, imphash_info = check_imphash(filepath)
    if imphash_match:
        detection_info["imphash_match"] = True
        name = imphash_info.get('name', 'Unknown')
        family = imphash_info.get('family', name)
        detection_info["details"].append(f"📦 IMPORT HASH MATCH: {name}")
        detection_info["matched_family"] = family
        confidence += 85
    
    # Read file content
    try:
        with open(filepath, 'rb') as f:
            file_content = f.read(1024 * 1024)
    except:
        file_content = None
    
    # 4. PATTERN MATCH
    pattern_match, pattern_name, pattern_score = check_pattern_match(filepath, file_content)
    if pattern_match == True:
        detection_info["pattern_match"] = True
        detection_info["pattern_confidence"] = pattern_score
        detection_info["details"].append(f"📊 PATTERN MATCH: {pattern_name} ({pattern_score}%)")
        detection_info["matched_family"] = pattern_name
        confidence += pattern_score
    elif pattern_match == "possible":
        detection_info["details"].append(f"📊 Possible pattern match: {pattern_name} ({pattern_score}%)")
        confidence += pattern_score * 0.5
    
    # 5. MACHINE LEARNING DETECTION
    if ml_model.is_trained:
        ml_match, ml_confidence, _ = ml_model.predict(filepath)
        if ml_match:
            detection_info["ml_match"] = True
            detection_info["ml_confidence"] = ml_confidence
            detection_info["details"].append(f"🤖 ML DETECTION: {ml_confidence:.1%} confidence")
            confidence += ml_confidence * 100
    
    # 6. SUSPICIOUS FILENAME
    filename = os.path.basename(filepath)
    for pattern in SUSPICIOUS_FILENAME_PATTERNS:
        if pattern.match(filename):
            detection_info["suspicious_name"] = True
            detection_info["details"].append(f"📁 Suspicious filename: {filename}")
            confidence += 20
            break
    
    # 7. SIGNATURE SCANNING
    if file_content:
        for sus_string in MALWARE_SIGNATURES["suspicious_strings"]:
            if sus_string in file_content:
                detection_info["signature_match"] = True
                detection_info["details"].append(f"🔤 Malicious string: {sus_string.decode('utf-8', errors='ignore')}")
                confidence += 30
                break
        
        packers_found = []
        for packer in MALWARE_SIGNATURES["packer_signatures"]:
            if packer in file_content:
                packers_found.append(packer.decode('utf-8', errors='ignore'))
        if packers_found:
            detection_info["details"].append(f"📦 Packed with: {', '.join(packers_found)}")
            confidence += 15 * len(packers_found)
        
        suspicious_apis_found = []
        for api in MALWARE_SIGNATURES["suspicious_apis"]:
            if api in file_content:
                suspicious_apis_found.append(api.decode('utf-8', errors='ignore'))
        
        if len(suspicious_apis_found) >= 3:
            detection_info["signature_match"] = True
            detection_info["details"].append(f"🔧 Multiple suspicious APIs ({len(suspicious_apis_found)} found)")
            confidence += 25
        elif suspicious_apis_found:
            detection_info["details"].append(f"🔧 Suspicious APIs: {', '.join(suspicious_apis_found[:3])}")
            confidence += 10
    
    # 8. ENTROPY
    try:
        entropy = calculate_entropy(filepath)
        if entropy > 7.0:
            detection_info["high_entropy"] = True
            detection_info["details"].append(f"🎲 High entropy ({entropy:.2f}) - possibly packed")
            confidence += 15
        elif entropy < 4.0:
            detection_info["details"].append(f"📝 Low entropy ({entropy:.2f}) - possibly script")
    except:
        pass
    
    detection_info["confidence"] = min(confidence, 100)
    
    is_malware = (
        detection_info["hash_match"] or
        detection_info["fuzzy_match"] or
        detection_info["imphash_match"] or
        detection_info["pattern_match"] or
        detection_info["ml_match"] or
        (detection_info["signature_match"] and detection_info["high_entropy"]) or
        (detection_info["suspicious_name"] and detection_info["signature_match"]) or
        confidence >= 60
    )
    
    return is_malware, detection_info, hashes

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
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/AppData/Local/Temp"),
        os.path.expanduser("~/AppData/Roaming"),
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
    """Main scanning function"""
    global _scan_cache, file_activity_by_pid, file_activity_global
    
    current_time = time.time()
    if not force_refresh and _scan_cache["last_result"] is not None:
        time_since_last = current_time - _scan_cache["last_scan_time"]
        if time_since_last < _scan_cache["cache_duration"]:
            print(f"⚡ Using cached scan results ({time_since_last:.1f}s old)")
            return _scan_cache["last_result"]
    
    print("🔍 Starting enhanced multi-layer AI scan...")
    
    with lock:
        file_activity_by_pid_snapshot = dict(file_activity_by_pid)
        file_activity_global_snapshot = file_activity_global
        file_activity_by_pid = defaultdict(int)
        file_activity_global = 0
    
    processes = []
    process_objects = {}
    all_processes_count = 0
    
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

    print(f"   Collecting data from {len(procs_to_monitor)} processes...")
    count = 0
    
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
            count += 1
            
            if count % 50 == 0:
                print(f"   Processed {count} processes...")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    print(f"✓ Collected {len(processes)} processes after filtering (Total: {all_processes_count})")
    
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
            if detection_info["signature_match"]:
                score += 4
                reasons.append("malicious_signatures")
            if detection_info["suspicious_name"]:
                score += 2
                reasons.append("suspicious_filename")
            if detection_info["high_entropy"]:
                score += 1
                reasons.append("high_entropy")
            
            detection_details = detection_info["details"]
            
            if detection_info.get("matched_family"):
                print(f"🚨 THREAT DETECTED: {name} - {detection_info['matched_family']} family (confidence: {detection_confidence}%)")
                reasons.append(f"family:{detection_info['matched_family']}")
            else:
                print(f"🚨 THREAT DETECTED: {name} - Confidence: {detection_confidence}%")

        # Behavioral checks
        if is_rare_path(exe_path):
            score += 0.5
            reasons.append("rare_path")

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
        
        if score >= 1:
            try:
                connections = len(proc_obj.net_connections()) if proc_obj else 0
                if connections > 100:
                    score += 1
                    reasons.append("high_connections")
                elif connections > 10:
                    score += 0.5
                    reasons.append("many_connections")
            except:
                pass
        
        if exe_path and os.path.isfile(exe_path):
            try:
                attrs = os.stat(exe_path).st_file_attributes
                if attrs & 0x2:
                    score += 2
                    reasons.append("hidden_file")
            except AttributeError:
                pass
        
        if proc_obj and score >= 1:
            try:
                children = proc_obj.children()
                recent_children = [c for c in children if time.time() - c.create_time() < 60]
                if len(recent_children) > 15:
                    score += 1
                    reasons.append("rapid_child_creation")
                elif len(recent_children) > 5:
                    score += 0.5
                    reasons.append("many_children")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if proc_obj and score >= 1:
            try:
                for c in proc_obj.children():
                    if c.name().lower() in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]:
                        score += 1
                        reasons.append("spawns_scripts")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        activity_count = file_activity_by_pid_snapshot.get(p["pid"], 0)
        if activity_count > 50:
            score += 1
            reasons.append("high_file_activity")
        elif activity_count > 20:
            score += 0.5
            reasons.append("file_activity")
        
        if file_activity_global_snapshot > 500:
            score += 1
            reasons.append("global_file_activity")

        # Determine severity
        if detection_info.get("hash_match"):
            severity = "confirmed_malware"
        elif detection_confidence >= 80:
            severity = "confirmed_malware"
        elif detection_confidence >= 60 or score >= 5:
            severity = "critical"
        elif detection_confidence >= 40 or score >= 3.5:
            severity = "warning"
        elif detection_confidence >= 20 or score >= 2:
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
        
        if (idx + 1) % 50 == 0:
            print(f"   Analyzed {idx + 1}/{len(processes)} processes...")

    result = {
        "total_processes": TOTAL,
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
    
    print(f"✓ Enhanced AI scan complete: {confirmed} confirmed, {critical} critical, {warning} warning, {suspicious} suspicious")
    
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
                    if alert.get('matched_family'):
                        title = f"🚨 CONFIRMED MALWARE: {alert['matched_family']} family"
                    else:
                        title = f"🚨 CONFIRMED MALWARE: {alert['name']}"
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
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Malware Scanner with AI Detection')
    parser.add_argument('--scan', action='store_true', help='Run scan')
    
    args = parser.parse_args()
    
    # Check if ML model is trained
    if not ml_model.is_trained:
        print("\n⚠ WARNING: ML model not trained!")
        print("   Run 'python ml_model.py' first to train the model using MalwareData.csv")
        print("   The scanner will still work using other detection methods.\n")
    
    observer = start_file_monitoring()
    print("=" * 60)
    print("🔍 ENHANCED MALWARE SCANNER WITH AI DETECTION")
    print("=" * 60)
    print(f"📊 Loaded {len(malware_hashes['sha256'])} SHA256 signatures")
    print(f"📊 Loaded {len(malware_hashes.get('imphash', {}))} IMPHASH signatures")
    print(f"📊 Loaded {len(malware_hashes.get('tlsh', {}))} TLSH fuzzy signatures")
    print(f"🤖 ML Model: {'READY' if ml_model.is_trained else 'NOT TRAINED'}")
    print("=" * 60)
    
    print("File monitoring started. Running enhanced AI scan...")
    result = scan_processes()
    print(f"\n📊 Scan Summary:")
    print(f"   Total processes: {result['total_processes']}")
    print(f"   Total alerts: {len(result['alerts'])}")
    print(f"   Safe processes: {len(result['safe'])}")
    
    if result['alerts']:
        print("\n🚨 ALERTS:")
        for alert in result['alerts']:
            confidence = alert.get('detection_confidence', 0)
            family = alert.get('matched_family', '')
            
            if family:
                print(f"  [{alert['severity'].upper()}] {alert['name']} (PID {alert['pid']})")
                print(f"       Family: {family}")
                print(f"       Confidence: {confidence}%")
            else:
                print(f"  [{alert['severity'].upper()}] {alert['name']} (PID {alert['pid']})")
            
            if alert.get('malware_info'):
                for detail in alert['malware_info'][:3]:
                    print(f"       → {detail}")
            print()
    
    print("\n👁️  Monitoring files... Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("\n👋 Scanner stopped.")