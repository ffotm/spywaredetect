const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');

let mainWindow;
let pythonProcess;
const BACKEND_PORT = 8000;

// Ensure log directory exists
const logDir = app.getPath('userData');
const logFile = path.join(logDir, 'app.log');

// Create log directory if it doesn't exist
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

function log(message) {
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] ${message}\n`;
    console.log(line.trim());
    try {
        fs.appendFileSync(logFile, line, { flag: 'a' });
    } catch (e) {
        console.error('Failed to write to log:', e);
    }
}

// Log startup info
log('=== APPLICATION STARTING ===');
log(`App version: ${app.getVersion()}`);
log(`Electron version: ${process.versions.electron}`);
log(`Node version: ${process.versions.node}`);
log(`Platform: ${process.platform}`);
log(`Is packaged: ${app.isPackaged}`);
log(`App path: ${app.getAppPath()}`);
log(`User data: ${app.getPath('userData')}`);
log(`Resources path: ${process.resourcesPath}`);

function checkBackendHealth() {
    return new Promise((resolve) => {
        const req = http.get(`http://127.0.0.1:${BACKEND_PORT}/health`, (res) => {
            // Accept any 2xx status code
            const success = res.statusCode >= 200 && res.statusCode < 300;
            log(`Health check response: ${res.statusCode} - ${success ? 'OK' : 'FAIL'}`);
            resolve(success);
        });

        req.on('error', (err) => {
            log(`Health check error: ${err.message}`);
            resolve(false);
        });

        req.on('timeout', () => {
            log('Health check timeout');
            req.destroy();
            resolve(false);
        });

        req.setTimeout(2000); // Increase timeout to 2 seconds

        req.end();
    });
}

async function waitForBackend(maxAttempts = 45) { // Increased from 30 to 45
    log(`Waiting for backend (max ${maxAttempts} attempts)...`);

    // Give server initial time to load malware signatures (this takes ~20 seconds)
    log('Giving backend time to initialize...');
    await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds before first check

    for (let i = 0; i < maxAttempts; i++) {
        const isHealthy = await checkBackendHealth();
        if (isHealthy) {
            log(`✓ Backend is ready after ${i + 1} attempts`);
            return true;
        }
        log(`Attempt ${i + 1}/${maxAttempts} - Backend not ready yet`);
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    log('✗ Backend failed to start within timeout period');
    return false;
}
async function startPythonBackend() {
    log('=== STARTING PYTHON BACKEND ===');

    const isPackaged = app.isPackaged;
    let pythonExecutable, scriptPath, cwd;

    if (isPackaged) {
        // Packaged paths
        const backendDir = path.join(process.resourcesPath, 'backend');
        const pythonDir = path.join(backendDir, 'python');

        log(`Backend directory: ${backendDir}`);
        log(`Python directory: ${pythonDir}`);

        // Check if directories exist
        log(`Backend exists: ${fs.existsSync(backendDir)}`);
        log(`Python dir exists: ${fs.existsSync(pythonDir)}`);

        // Try to find python.exe
        const pythonExe = path.join(pythonDir, 'python.exe');
        log(`Python.exe path: ${pythonExe}`);
        log(`Python.exe exists: ${fs.existsSync(pythonExe)}`);

        if (fs.existsSync(pythonExe)) {
            pythonExecutable = pythonExe;
        } else {
            log('Embedded Python not found, trying system Python');
            pythonExecutable = 'python';
        }

        scriptPath = path.join(backendDir, 'api.py');
        cwd = backendDir;

        // List backend directory contents
        if (fs.existsSync(backendDir)) {
            const files = fs.readdirSync(backendDir);
            log(`Backend directory contents: ${files.join(', ')}`);
        }

    } else {
        // Development paths
        pythonExecutable = 'python';
        scriptPath = path.join(__dirname, '..', 'backend', 'api.py');
        cwd = path.join(__dirname, '..', 'backend');
    }

    log(`Python executable: ${pythonExecutable}`);
    log(`Script path: ${scriptPath}`);
    log(`Working directory: ${cwd}`);
    log(`Script exists: ${fs.existsSync(scriptPath)}`);

    if (!fs.existsSync(scriptPath)) {
        const error = `CRITICAL: Script not found at: ${scriptPath}`;
        log(error);
        throw new Error(error);
    }

    // Create Python log files
    const pythonStdoutLog = path.join(logDir, 'python_stdout.log');
    const pythonStderrLog = path.join(logDir, 'python_stderr.log');

    log(`Python stdout log: ${pythonStdoutLog}`);
    log(`Python stderr log: ${pythonStderrLog}`);

    const stdoutStream = fs.createWriteStream(pythonStdoutLog, { flags: 'a' });
    const stderrStream = fs.createWriteStream(pythonStderrLog, { flags: 'a' });

    log('Spawning Python process...');

    try {
        pythonProcess = spawn(pythonExecutable, [scriptPath], {
            cwd: cwd,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: false, // Show window for debugging
            env: {
                ...process.env,
                PORT: BACKEND_PORT.toString(),
                PYTHONUNBUFFERED: '1'

            }
        });

        log(`Python process spawned with PID: ${pythonProcess.pid}`);

        pythonProcess.stdout.pipe(stdoutStream);
        pythonProcess.stderr.pipe(stderrStream);

        pythonProcess.stdout.on('data', (data) => {
            const message = data.toString().trim();
            if (message) log(`[PYTHON OUT] ${message}`);
        });

        pythonProcess.stderr.on('data', (data) => {
            const message = data.toString().trim();
            if (message) log(`[PYTHON ERR] ${message}`);
        });

        pythonProcess.on('error', (err) => {
            log(`[PYTHON ERROR] Failed to start: ${err.message}`);
            log(`Error code: ${err.code}`);
            log(`Error stack: ${err.stack}`);
        });

        pythonProcess.on('exit', (code, signal) => {
            log(`[PYTHON EXIT] Code: ${code}, Signal: ${signal}`);
            pythonProcess = null;
        });

        log('Python process setup complete');

    } catch (err) {
        log(`Exception spawning Python: ${err.message}`);
        throw err;
    }
}

function getFrontendPath() {
    if (!app.isPackaged) return null;

    const possiblePaths = [
        path.join(process.resourcesPath, 'app', 'out'),
        path.join(process.resourcesPath, 'out'),
        path.join(__dirname, '..', 'out'),
    ];

    log('=== SEARCHING FOR FRONTEND ===');
    for (const p of possiblePaths) {
        const indexPath = path.join(p, 'index.html');
        log(`Checking: ${indexPath}`);
        log(`Exists: ${fs.existsSync(indexPath)}`);
        if (fs.existsSync(indexPath)) {
            log(`✓ Found frontend at: ${p}`);
            return p;
        }
    }

    log('✗ Frontend not found in any location');
    return null;
}

async function createWindow() {
    log('=== CREATING WINDOW ===');

    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        backgroundColor: '#030712',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        },
        autoHideMenuBar: true,
        title: 'Malware Detector',
        show: false,
        icon: path.join(__dirname, '..', 'public', 'icon.ico')
    });

    // Loading screen
    mainWindow.loadURL(`data:text/html,
        <html>
        <body style="background: #030712; color: white; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
            <div style="text-align: center;">
                <h1 style="font-size: 32px; margin-bottom: 20px;">Malware Detector</h1>
                <div style="border: 3px solid #3b82f6; border-radius: 50%; border-top-color: transparent; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 0 auto;"></div>
                <p style="margin-top: 20px; color: #9ca3af;">Starting backend services...</p>
                <p style="margin-top: 10px; color: #6b7280; font-size: 12px;">Check logs at: ${logDir}</p>
            </div>
            <style>
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            </style>
        </body>
        </html>
    `);

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        log('Window shown');
    });

    // Wait for backend
    log('Waiting for backend to be ready...');
    const backendReady = await waitForBackend();

    if (!backendReady) {
        log('Backend failed to start - showing error dialog');
        dialog.showErrorBox(
            'Backend Error',
            `Failed to start the backend server.\n\nLogs saved to:\n${logDir}\n\nPlease check:\n- python_stdout.log\n- python_stderr.log\n- app.log`
        );
        return; // Don't quit, let user see logs
    }

    // Load frontend
    const frontendPath = getFrontendPath();

    if (app.isPackaged) {
        if (frontendPath) {
            const indexPath = path.join(frontendPath, 'index.html');
            log(`Loading frontend: ${indexPath}`);

            mainWindow.loadFile(indexPath).catch(err => {
                log(`Error loading frontend: ${err.message}`);
                dialog.showErrorBox('Error', `Failed to load application.\n\n${err.message}`);
            });
        } else {
            log('Frontend not found - showing error');
            dialog.showErrorBox('Error', 'Application files not found. Please reinstall.');
        }
    } else {
        log('Development mode - loading dev server');
        mainWindow.loadURL('http://localhost:3000').catch(err => {
            log(`Dev server error: ${err.message}`);
        });
    }

    mainWindow.on('closed', () => {
        log('Window closed');
        mainWindow = null;
    });
}

app.whenReady().then(async() => {
    log('=== APP READY ===');

    try {
        await startPythonBackend();
        await createWindow();
    } catch (error) {
        log(`FATAL ERROR: ${error.message}`);
        log(`Stack: ${error.stack}`);

        dialog.showErrorBox(
            'Startup Error',
            `Failed to start application.\n\n${error.message}\n\nLogs: ${logDir}`
        );
    }

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    log('All windows closed');
    if (pythonProcess) {
        log('Killing Python process');
        try {
            pythonProcess.kill('SIGTERM');
        } catch (e) {
            log(`Error killing Python: ${e.message}`);
        }
    }
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', () => {
    log('App quitting');
    if (pythonProcess) {
        try {
            pythonProcess.kill('SIGTERM');
        } catch (e) {
            log(`Error killing Python: ${e.message}`);
        }
    }
});

app.on('will-quit', () => {
    log('=== APPLICATION SHUTTING DOWN ===');
});