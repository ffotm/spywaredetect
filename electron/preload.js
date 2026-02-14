const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
    getBackendUrl: () => ipcRenderer.invoke('get-backend-url')
});