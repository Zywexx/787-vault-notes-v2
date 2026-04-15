/**
 * 787 Vault — Preload (hardened)
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    loadVault: () => ipcRenderer.invoke('vault:load'),
    saveVault: (data) => ipcRenderer.invoke('vault:save', data),
    secureDelete: () => ipcRenderer.invoke('vault:secure-delete'),
    generateSalt: () => ipcRenderer.invoke('crypto:generateSalt'),
    generateSecureId: () => ipcRenderer.invoke('crypto:generateId'),
    deriveScryptKeyMaterial: (password, saltHex) =>
        ipcRenderer.invoke('crypto:deriveScryptKeyMaterial', { password, saltHex }),
    selectFiles: () => ipcRenderer.invoke('dialog:openFile'),
    saveBackup: (content) => ipcRenderer.invoke('backup:save', content),
    openBackup: () => ipcRenderer.invoke('backup:open'),
    onBeforeClose: (callback) => {
        ipcRenderer.on('app:before-close', () => {
            callback();
        });
    },
    confirmQuit: () => ipcRenderer.send('app:quit-confirmed'),
    forceClose: () => ipcRenderer.send('app:force-close'),
});
