const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PYTHON_VERSION = '3.11.9';
const PYTHON_URL = `https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-amd64.zip`;
const DOWNLOAD_PATH = path.join(__dirname, 'python-embed.zip');
const EXTRACT_PATH = path.join(__dirname, 'python-embedded');

console.log('Downloading embedded Python...');
console.log(`URL: ${PYTHON_URL}`);

// Clean up old files
if (fs.existsSync(DOWNLOAD_PATH)) {
    try {
        fs.unlinkSync(DOWNLOAD_PATH);
        console.log('Cleaned up old download');
    } catch (e) {
        console.log('Could not delete old download:', e.message);
    }
}

// Create extract directory
if (!fs.existsSync(EXTRACT_PATH)) {
    fs.mkdirSync(EXTRACT_PATH, { recursive: true });
}

// Download file
const file = fs.createWriteStream(DOWNLOAD_PATH);

https.get(PYTHON_URL, (response) => {
    response.pipe(file);

    file.on('finish', () => {
        file.close(() => {
            console.log('Download complete!');

            // Wait a bit for file to be fully closed
            setTimeout(() => {
                extractPython();
            }, 1000);
        });
    });
}).on('error', (err) => {
    fs.unlink(DOWNLOAD_PATH, () => {});
    console.error('Download failed:', err.message);
    process.exit(1);
});

function extractPython() {
    console.log('Extracting Python...');

    try {
        // Use unzip command if available, otherwise use PowerShell
        try {
            // Try using tar (available on Windows 10+)
            execSync(`tar -xf "${DOWNLOAD_PATH}" -C "${EXTRACT_PATH}"`, {
                stdio: 'inherit'
            });
            console.log('Extraction complete!');
        } catch (e) {
            // Fallback to PowerShell with better command
            const psCommand = `
                $ProgressPreference = 'SilentlyContinue';
                Add-Type -AssemblyName System.IO.Compression.FileSystem;
                [System.IO.Compression.ZipFile]::ExtractToDirectory('${DOWNLOAD_PATH.replace(/\\/g, '\\\\')}', '${EXTRACT_PATH.replace(/\\/g, '\\\\')}', $true);
            `;

            execSync(`powershell -NoProfile -Command "${psCommand}"`, {
                stdio: 'inherit'
            });
            console.log('Extraction complete!');
        }

        // Verify extraction
        const pythonExe = path.join(EXTRACT_PATH, 'python.exe');
        if (!fs.existsSync(pythonExe)) {
            throw new Error('Python.exe not found after extraction');
        }

        // Clean up zip file
        fs.unlinkSync(DOWNLOAD_PATH);
        console.log('Cleaned up zip file');

        // Install pip
        installPip();

    } catch (error) {
        console.error('Extraction error:', error.message);
        console.log('\nTrying manual extraction...');
        manualExtract();
    }
}

function manualExtract() {
    console.log('Please manually extract the zip file:');
    console.log(`1. Open: ${DOWNLOAD_PATH}`);
    console.log(`2. Extract to: ${EXTRACT_PATH}`);
    console.log('3. Press Enter when done...');

    process.stdin.once('data', () => {
        const pythonExe = path.join(EXTRACT_PATH, 'python.exe');
        if (fs.existsSync(pythonExe)) {
            installPip();
        } else {
            console.error('Python.exe still not found. Please extract manually.');
            process.exit(1);
        }
    });
}

function installPip() {
    console.log('\nInstalling pip...');

    const pythonExe = path.join(EXTRACT_PATH, 'python.exe');
    const getPipPath = path.join(EXTRACT_PATH, 'get-pip.py');

    // Download get-pip.py
    const getPipFile = fs.createWriteStream(getPipPath);

    https.get('https://bootstrap.pypa.io/get-pip.py', (response) => {
        response.pipe(getPipFile);

        getPipFile.on('finish', () => {
            getPipFile.close(() => {
                console.log('Downloaded get-pip.py');

                // Wait a bit
                setTimeout(() => {
                    try {
                        // Modify python path to enable pip
                        modifyPythonPath();

                        // Run get-pip.py
                        console.log('Running get-pip.py...');
                        execSync(`"${pythonExe}" "${getPipPath}"`, {
                            stdio: 'inherit',
                            cwd: EXTRACT_PATH
                        });

                        console.log('Pip installed successfully!');

                        // Install dependencies
                        installDependencies();

                    } catch (error) {
                        console.error('Pip installation error:', error.message);
                        console.log('\nYou can manually install dependencies later with:');
                        console.log(`"${pythonExe}" -m pip install -r backend/requirements.txt`);
                        process.exit(1);
                    }
                }, 500);
            });
        });
    }).on('error', (err) => {
        console.error('Failed to download get-pip.py:', err.message);
        process.exit(1);
    });
}

function modifyPythonPath() {
    // Enable site-packages for embedded Python
    const pythonPth = path.join(EXTRACT_PATH, `python${PYTHON_VERSION.substring(0, 2)}._pth`);

    if (fs.existsSync(pythonPth)) {
        let content = fs.readFileSync(pythonPth, 'utf8');

        // Uncomment import site
        content = content.replace('#import site', 'import site');

        // Add Lib/site-packages
        if (!content.includes('Lib\\site-packages')) {
            content += '\nLib\\site-packages\n';
        }

        fs.writeFileSync(pythonPth, content);
        console.log('Modified Python path configuration');
    }
}

function installDependencies() {
    console.log('\nInstalling Python dependencies...');
    console.log('This may take a few minutes...');

    const pythonExe = path.join(EXTRACT_PATH, 'python.exe');
    const requirementsPath = path.join(__dirname, 'backend', 'requirements.txt');

    if (!fs.existsSync(requirementsPath)) {
        console.error('requirements.txt not found at:', requirementsPath);
        console.log('Please create backend/requirements.txt with your dependencies');
        process.exit(1);
    }

    try {
        execSync(`"${pythonExe}" -m pip install -r "${requirementsPath}"`, {
            stdio: 'inherit',
            cwd: EXTRACT_PATH
        });

        console.log('\n✓ Setup complete!');
        console.log('\nYou can now run:');
        console.log('  npm run electron:dev  - Test in development');
        console.log('  npm run package       - Build installer');

    } catch (error) {
        console.error('\nDependency installation failed:', error.message);
        console.log('\nYou can manually install with:');
        console.log(`"${pythonExe}" -m pip install -r "${requirementsPath}"`);
        process.exit(1);
    }
}