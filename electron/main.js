const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow;
let pythonProcess;

const BACKEND_PORT = 8000;

function log(message) {
    console.log(`[Main] ${message}`);
}
mainWindow.webContents.openDevTools();

function startPythonBackend() {
    return new Promise((resolve) => {
        log('Starting Python backend...');

        const isPackaged = app.isPackaged;
        let pythonExecutable, scriptPath, cwd;

        if (isPackaged) {
            // When packaged, Python is bundled in resources
            const possiblePythonPaths = [
                path.join(process.resourcesPath, 'backend', 'python', 'python.exe'),
                path.join(process.resourcesPath, 'python', 'python.exe'),
                'python' // Fallback to system Python
            ];

            // Find the first valid Python executable
            pythonExecutable = possiblePythonPaths.find(p => {
                try {
                    return p === 'python' || fs.existsSync(p);
                } catch {
                    return false;
                }
            }) || 'python';

            scriptPath = path.join(process.resourcesPath, 'backend', 'api.py');
            cwd = path.join(process.resourcesPath, 'backend');
        } else {
            pythonExecutable = 'python';
            scriptPath = path.join(__dirname, '..', 'backend', 'api.py');
            cwd = path.join(__dirname, '..', 'backend');
        }

        log(`Python: ${pythonExecutable}`);
        log(`Script: ${scriptPath}`);

        // Check if script exists
        if (!fs.existsSync(scriptPath)) {
            log(`Script not found at: ${scriptPath}`);
            resolve(); // Continue even if script not found
            return;
        }

        pythonProcess = spawn(pythonExecutable, [scriptPath], {
            cwd: cwd,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
            env: {
                ...process.env,
                PORT: BACKEND_PORT.toString()
            }
        });

        pythonProcess.stdout.on('data', (data) => log(`Backend: ${data}`));
        pythonProcess.stderr.on('data', (data) => log(`Backend Error: ${data}`));

        pythonProcess.on('error', (err) => {
            log(`Failed to start Python: ${err}`);
        });

        // Give Python time to start
        setTimeout(() => resolve(), 3000);
    });
}

function getFrontendPath() {
    if (app.isPackaged) {
        // In production, try multiple possible locations
        const possiblePaths = [
            path.join(process.resourcesPath, 'app', 'out'), // If using resourcesPath/app/out
            path.join(process.resourcesPath, 'out'), // If using resourcesPath/out
            path.join(__dirname, '..', 'out'), // Relative to electron main.js
            path.join(app.getAppPath(), 'out'), // App path
        ];

        for (const p of possiblePaths) {
            const indexPath = path.join(p, 'index.html');
            log(`Checking path: ${indexPath}`);
            if (fs.existsSync(indexPath)) {
                log(`Found frontend at: ${p}`);
                return p;
            }
        }

        log('Frontend not found in any expected location');
        return null;
    } else {
        // In development, use the dev server
        return 'http://localhost:3000';
    }
}

function createWindow() {
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
                <p style="margin-top: 20px; color: #9ca3af;">Loading application...</p>
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
    });

    // Load the frontend
    setTimeout(async() => {
        const frontendPath = getFrontendPath();

        if (app.isPackaged) {
            // Production - load from static files
            if (frontendPath) {
                const indexPath = path.join(frontendPath, 'index.html');
                log(`Loading static file: ${indexPath}`);

                mainWindow.loadFile(indexPath).catch(err => {
                    log(`Error loading static file: ${err}`);
                    dialog.showErrorBox('Error',
                        `Failed to load application.\n\nPath: ${indexPath}\n\nError: ${err.message}`);
                });
            } else {
                dialog.showErrorBox('Error',
                    'Application files not found. Please reinstall the application.');
            }
        } else {
            // Development - load from dev server
            mainWindow.loadURL('http://localhost:3000').catch(err => {
                log(`Error loading dev server: ${err}`);
                dialog.showErrorBox('Connection Error',
                    `Could not connect to Next.js dev server.\n\nMake sure to run 'npm run dev' first.\n\nError: ${err.message}`);
            });
        }
    }, 4000);

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.whenReady().then(async() => {
    await startPythonBackend();
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (pythonProcess) {
        try {
            pythonProcess.kill();
        } catch (e) {
            log(`Error killing Python process: ${e}`);
        }
    }
    app.quit();
});

app.on('before-quit', () => {
    if (pythonProcess) {
        try {
            pythonProcess.kill();
        } catch (e) {
            log(`Error killing Python process: ${e}`);
        }
    }
});