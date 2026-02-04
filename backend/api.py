from fastapi import FastAPI
from scanner import scan_processes, stream_processes
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import json


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/scan")
def scan():
    return scan_processes()


@app.get("/scan/stream")
def scan_stream():
    def event_generator():
        for data in stream_processes():
            yield f"data: {json.dumps(data)}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")




@app.get("/")
def read_root():
    return {"message": "Spyware Detection API is running."}
  



