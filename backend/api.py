import sys
import os
from pathlib import Path

# CRITICAL: Add backend directory to Python path for local imports
backend_dir = Path(__file__).parent.resolve()
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI
from scanner import scan_processes, stream_processes, store_scan_results
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import json


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/scan")
def scan():
    """Quick scan without database storage"""
    return scan_processes()


@app.get("/scan/stream")
def scan_stream():
    """Stream process information in real-time"""
    def event_generator():
        for data in stream_processes():
            yield f"data: {json.dumps(data)}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/scan/store") 
def store_scan():
    """Scan and save results to database AFTER scan completes"""
    # 1. Run the full scan first (fast, no DB calls)
    scan_data = scan_processes()
    
    # 2. Store everything to database AFTER scan is done
    scan_id = store_scan_results(scan_data)
    
    # 3. Return scan data with scan_id
    scan_data['scan_id'] = scan_id
    return scan_data


@app.get("/")
def read_root():
    return {"message": "Detection API is running."}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting Malware Detection API on port {port}...", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")