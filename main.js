/**
 * 787 Vault — Main Process (hardened)
 *
 * Secure deletion: multi-pass overwrite reduces casual recovery of the previous
 * vault file on spinning disks. SSDs with TRIM/wear-leveling may still retain
 * data in flash cells; OS-level full-disk encryption is the practical defense.
 */

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let mainWindow;
/** İkinci close denemesinde pencereyi gerçekten kapat (çıkış onayından sonra) */
let allowMainWindowClose = false;

/** Scrypt parameters (N=2^17, r=8, p=1) — compensates for unrestricted passwords */
const SCRYPT_PARAMS = {
    N: 131072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
};

const DERIVED_KEY_BYTES = 64;

function getVaultPath() {
    return path.join(app.getPath('userData'), 'vault.json');
}

function vaultLog(code) {
    if (process.env.NODE_ENV === 'development') {
        console.error('[787-vault]', code);
    }
}

/**
 * Overwrite existing vault file with multiple patterns before replacement.
 */
function secureOverwriteFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    const size = fs.statSync(filePath).size;
    if (size === 0) {
        fs.unlinkSync(filePath);
        return;
    }
    const fd = fs.openSync(filePath, 'r+');
    try {
        const passes = [
            Buffer.alloc(size, 0x00),
            Buffer.alloc(size, 0xff),
            crypto.randomBytes(size),
        ];
        for (const buf of passes) {
            fs.writeSync(fd, buf, 0, size, 0);
            fs.fsyncSync(fd);
        }
    } finally {
        fs.closeSync(fd);
    }
    fs.unlinkSync(filePath);
}

function writeVaultAtomic(jsonString) {
    const vp = getVaultPath();
    const dir = path.dirname(vp);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const tmp = `${vp}.${crypto.randomBytes(4).readUInt32LE(0).toString(16)}.tmp`;
    fs.writeFileSync(tmp, jsonString, { encoding: 'utf8', mode: 0o600 });
    let tmpFd;
    try {
        tmpFd = fs.openSync(tmp, 'r+');
        fs.fsyncSync(tmpFd);
    } finally {
        if (tmpFd !== undefined) fs.closeSync(tmpFd);
    }

    secureOverwriteFile(vp);

    try {
        fs.renameSync(tmp, vp);
    } catch (e) {
        try {
            fs.unlinkSync(tmp);
        } catch (_) { /* ignore */ }
        throw e;
    }
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 750,
        icon: path.join(__dirname, '787.ico'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            enableRemoteModule: false,
            allowRunningInsecureContent: false,
            /* Pencere arka plandayken işleyici / giriş kısıtlanmasını azaltır */
            backgroundThrottling: false,
        },
        autoHideMenuBar: true,
        backgroundColor: '#000000',
        title: '787 Vault',
    });

    mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));

    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        try {
            const u = new URL(url);
            if (u.protocol === 'https:' || u.protocol === 'http:') {
                shell.openExternal(url);
            }
        } catch (_) {
            /* ignore */
        }
        return { action: 'deny' };
    });

    mainWindow.on('close', (e) => {
        if (allowMainWindowClose) return;
        e.preventDefault();
        if (!mainWindow.isDestroyed()) {
            mainWindow.webContents.send('app:before-close');
        }
    });
}

app.on('ready', createWindow);
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('crypto:generateSalt', async () => {
    return crypto.randomBytes(16).toString('hex');
});

ipcMain.handle('crypto:generateId', async () => {
    return crypto.randomUUID();
});

/**
 * Derive 64 bytes via scrypt: first 32 = AES-256, next 32 = HMAC-SHA256 key material.
 * Password is not logged. Returns base64 for IPC serialization.
 */
ipcMain.handle('crypto:deriveScryptKeyMaterial', async (_e, { password, saltHex }) => {
    try {
        if (typeof password !== 'string' || typeof saltHex !== 'string') {
            throw new Error('INVALID_INPUT');
        }
        const salt = Buffer.from(saltHex, 'hex');
        if (salt.length < 16) throw new Error('INVALID_SALT');
        const derived = crypto.scryptSync(password, salt, DERIVED_KEY_BYTES, SCRYPT_PARAMS);
        return { ok: true, materialB64: derived.toString('base64') };
    } catch (e) {
        vaultLog('scrypt_derive_failed');
        return { ok: false, error: 'KEY_DERIVATION_FAILED' };
    }
});

ipcMain.handle('vault:load', async () => {
    try {
        const vp = getVaultPath();
        if (!fs.existsSync(vp)) {
            return { notes: [], salt: null, verifier: null, hmac: null, kdf: null, vaultFormatVersion: 2 };
        }
        const raw = fs.readFileSync(vp, 'utf8');
        const data = JSON.parse(raw);
        if (!data || typeof data !== 'object') {
            vaultLog('vault_parse_invalid');
            return { error: 'INVALID_VAULT_FILE' };
        }
        return data;
    } catch (e) {
        vaultLog('vault_load_failed');
        return { error: 'FAILED_TO_LOAD_VAULT' };
    }
});

ipcMain.handle('vault:save', async (_e, data) => {
    try {
        if (!data || typeof data !== 'object') {
            return { error: 'INVALID_SAVE_PAYLOAD' };
        }
        const jsonString = JSON.stringify(data, null, 2);
        writeVaultAtomic(jsonString);
        return { success: true };
    } catch (e) {
        vaultLog('vault_save_failed');
        return { error: 'FAILED_TO_SAVE_VAULT' };
    }
});

ipcMain.handle('vault:secure-delete', async () => {
    try {
        const vp = getVaultPath();
        secureOverwriteFile(vp);
        return { success: true };
    } catch (e) {
        vaultLog('vault_secure_delete_failed');
        return { error: 'FAILED_TO_SECURE_DELETE' };
    }
});

ipcMain.handle('dialog:openFile', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openFile', 'multiSelections'],
        filters: [{ name: 'Text Files', extensions: ['txt', 'md'] }],
    });
    if (result.canceled) return [];
    return result.filePaths.map((fp) => ({
        name: path.basename(fp),
        content: fs.readFileSync(fp, 'utf8'),
    }));
});

ipcMain.handle('backup:save', async (_e, content) => {
    try {
        if (typeof content !== 'string') return { error: 'INVALID_BACKUP' };
        const r = await dialog.showSaveDialog(mainWindow, {
            title: 'Not yedeğini kaydet',
            defaultPath: `787-vault-yedek-${new Date().toISOString().slice(0, 10)}.787bak`,
            filters: [
                { name: '787 Yedek', extensions: ['787bak', 'json'] },
                { name: 'Tüm dosyalar', extensions: ['*'] },
            ],
        });
        if (r.canceled || !r.filePath) return { canceled: true };
        fs.writeFileSync(r.filePath, content, { encoding: 'utf8', mode: 0o600 });
        return { success: true, path: r.filePath };
    } catch (e) {
        vaultLog('backup_save_failed');
        return { error: 'BACKUP_SAVE_FAILED' };
    }
});

ipcMain.handle('backup:open', async () => {
    try {
        const r = await dialog.showOpenDialog(mainWindow, {
            title: 'Yedek dosyası seç',
            properties: ['openFile'],
            filters: [
                { name: '787 Yedek', extensions: ['787bak', 'json'] },
                { name: 'Tüm dosyalar', extensions: ['*'] },
            ],
        });
        if (r.canceled || !r.filePaths || !r.filePaths[0]) return { canceled: true };
        const raw = fs.readFileSync(r.filePaths[0], 'utf8');
        return { content: raw, path: r.filePaths[0] };
    } catch (e) {
        vaultLog('backup_open_failed');
        return { error: 'BACKUP_OPEN_FAILED' };
    }
});

ipcMain.on('app:quit-confirmed', () => {
    allowMainWindowClose = true;
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.close();
    } else {
        app.quit();
    }
});

ipcMain.on('app:force-close', () => {
    allowMainWindowClose = true;
    app.quit();
});
