from supabase import create_client, Client
import os
from datetime import datetime
from dotenv import load_dotenv
import json

load_dotenv()  # Load environment variables from .env 

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class Database:
    def __init__(self):
        self.client = supabase 
    
    def create_scan(self, scan_type: str = "quick"): 
        scan = self.client.table("scans").insert({
            "scan_type": scan_type,
            "status": "running",
            "started_at": datetime.utcnow().isoformat()
        }).execute()
        return scan.data[0]["id"]

    def complete_scan(self, risk_level: str, risk_score: int, scan_id: str, status: str = "completed"):
        self.client.table("scans").update({
            "risk_level": risk_level,
            "risk_score": risk_score,
            "status": status,
            "finished_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()
    
    def log_process(self, scan_id: str, process_id: int, name: str, path: str, 
                    score: int, threads: int, connections: int, reasons: list, 
                    severity: str, signed: bool, cpu_usage: float = 0, memory_usage: float = 0):
       
        result = self.client.table("processes").insert({
            "scan_id": scan_id,
            "process_name": name,
            "pid": process_id,
            "path": path,
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "threads": threads,
            "connections": connections,
            "suspicious": score >= 2,
            "signed": signed
        }).execute()
        
        # Return the UUID of the inserted process
        if result.data and len(result.data) > 0:
            return result.data[0]["id"]
        return None

    def mark_process_suspicious(self, process_id: str):
       
        self.client.table("processes").update({
            "suspicious": True
        }).eq("id", process_id).execute()

    def log_alert(self, scan_id: str, process_uuid: str, severity: str, 
                  title: str, path: str, score: int, reasons: list):
      
        self.client.table("alerts").insert({
            "scan_id": scan_id,
            "process_id": process_uuid,  # This is the UUID from processes table
            "severity": severity,
            "title": title,
            "description": ", ".join(reasons),
            "path": path,
            "score": score,
            "related_process": title.replace("Suspicious Process: ", ""),
            "created_at": datetime.utcnow().isoformat()
        }).execute()

    def log_device(self, user_id: str, device_name: str, os: str):
        device = self.client.table("devices").insert({
            "user_id": user_id,
            "device_name": device_name,
            "os": os,
            "last_seen": datetime.utcnow().isoformat()
        }).execute()
        return device.data[0]["id"]