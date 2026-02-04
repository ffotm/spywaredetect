from fastapi import FastAPI
from scanner import scan_processes
import psutil

app = FastAPI()

@app.get("/scan")
def scan():
    return scan_processes()
