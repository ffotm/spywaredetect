//electron/preload.js
const { contextBridge } = require('electron');

// Expose a safe API to the renderer process
contextBridge.exposeInMainWorld('electronAPI', {
    getBackendUrl: () => 'http://localhost:8000' // Always point to localhost:8000
});