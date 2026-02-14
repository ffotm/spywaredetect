const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess;
let nextProcess;

const BACKEND_PORT = 8000;
const FRONTEND_PORT = 3000;

function startPythonBackend() {
    console.log('Starting Python backend...');

    // In packaged app, Python is in resources
    const isPackaged = app.isPackaged;

    const pythonExecutable = isPackaged ?
        path.join(process.resourcesPath, 'backend', 'python', 'python.exe') :
        'python';

    const scriptPath = isPackaged ?
        path.join(process.resourcesPath, 'backend', 'api.py') :
        path.join(__dirname, '..', 'backend', 'api.py');

    const cwd = isPackaged ?
        path.join(process.resourcesPath, 'backend') :
        path.join(__dirname, '..', 'backend');

    console.log('Python executable:', pythonExecutable);
    console.log('Script path:', scriptPath);

    pythonProcess = spawn(pythonExecutable, [scriptPath], { cwd });

    pythonProcess.stdout.on('data', (data) => {
        console.log(`Backend: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Backend: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Backend process exited with code ${code}`);
    });

    return new Promise((resolve) => {
        setTimeout(resolve, 3000);
    });
}

function startNextDev() {
    console.log('Starting Next.js dev server...');

    const isPackaged = app.isPackaged;

    // In packaged app, Next.js code is in resources
    const cwd = isPackaged ?
        path.join(process.resourcesPath, 'app') :
        path.join(__dirname, '..');

    console.log('Next.js working directory:', cwd);

    // Start Next.js dev server
    nextProcess = spawn('npm', ['run', 'dev'], {
        cwd: cwd,
        shell: true,
        env: {
            ...process.env,
            PORT: FRONTEND_PORT.toString()
        }
    });

    nextProcess.stdout.on('data', (data) => {
        console.log(`Next.js: ${data}`);
    });

    nextProcess.stderr.on('data', (data) => {
        console.log(`Next.js: ${data}`);
    });

    nextProcess.on('close', (code) => {
        console.log(`Next.js process exited with code ${code}`);
    });

    return new Promise((resolve) => {
        // Wait longer for Next.js to compile and start
        setTimeout(resolve, 8000);
    });
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        backgroundColor: '#030712',
        icon: path.join(__dirname, '..', 'icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true
        },
        autoHideMenuBar: true,
        title: 'Malware Detector'
    });

    // Show loading screen while waiting for Next.js
    mainWindow.loadURL(`data:text/html,
        <html>
        <body style="background: #030712; color: white; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
            <div style="text-align: center;">
                <h1>Malware Detector</h1>
                <p>Starting application...</p>
                <p style="font-size: 12px; color: #666;">This may take a few seconds</p>
            </div>
        </body>
        </html>
    `);

    // Load Next.js dev server after delay
    setTimeout(() => {
        mainWindow.loadURL(`http://localhost:${FRONTEND_PORT}`);
    }, 8000);

    // Uncomment for debugging
    // mainWindow.webContents.openDevTools();

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.whenReady().then(async() => {
    await startPythonBackend();
    await startNextDev();
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    // Kill all processes
    if (pythonProcess) {
        pythonProcess.kill();
    }
    if (nextProcess) {
        nextProcess.kill();
    }

    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('before-quit', () => {
    if (pythonProcess) {
        pythonProcess.kill();
    }
    if (nextProcess) {
        nextProcess.kill();
    }
});