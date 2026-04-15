/**
 * 787 Vault — Renderer (hardened)
 *
 * Native memory locking (mlock): CryptoKey material lives inside the browser
 * process; true RAM pinning requires a native Node addon or OS-specific APIs.
 */

// ============================================================
// SESSION (no long-lived plaintext passwords or key exports)
// ============================================================
const Session = (() => {
    let masterKey = null;
    let hmacKey = null;
    return {
        setKeys(m, h) {
            masterKey = m;
            hmacKey = h;
        },
        clear() {
            masterKey = null;
            hmacKey = null;
        },
        getMaster() {
            return masterKey;
        },
        getHmac() {
            return hmacKey;
        },
        isUnlocked() {
            return masterKey !== null;
        },
    };
})();

// ============================================================
// STATE
// ============================================================
let currentVault = {
    notes: [],
    salt: null,
    verifier: null,
    hmac: null,
    kdf: null,
    vaultFormatVersion: 2,
    hmacVersion: 2,
};
let activeNoteId = null;
let currentView = 'hub';
let inactivityTimer;
const INACTIVITY_LIMIT = 5 * 60 * 1000;

/** Lazy title cache — cleared on lock, blur, visibility hidden */
const decryptedTitleCache = new Map();

const $ = (id) => document.getElementById(id);

const lockScreen = $('lock-screen');
const mainPanel = $('main-panel');
const passwordInput = $('master-password');
const unlockBtn = $('unlock-btn');
const lockError = $('lock-error');
const notesList = $('notes-list');
const noteTitle = $('note-title');
const noteContent = $('note-content');
const saveBtn = $('save-note-btn');
const deleteBtn = $('delete-note-btn');
const newNoteBtn = $('new-note-btn');
const lockAppBtn = $('lock-app-btn');
const toastContainer = $('toast-container');

const navHub = $('nav-hub');
const navSecurity = $('nav-security');

const hubView = $('hub-view');
const noteView = $('note-view');
const securityView = $('security-view');

const statCount = $('stat-count');

const oldPasswordInput = $('old-password');
const newPasswordInput = $('new-password');
const changePasswordBtn = $('change-password-btn');
const changePwdError = $('change-pwd-error');
const wipePasswordInput = $('wipe-password');
const wipeAllBtn = $('wipe-all-btn');
const wipeError = $('wipe-error');

const noteSearchInput = $('note-search');
const noteSearchContent = $('note-search-content');
const backupExportBtn = $('backup-export-btn');
const backupImportBtn = $('backup-import-btn');

let searchTimer = null;
/** null = filtre yok; Set = eşleşen not id'leri */
let searchResultIds = null;

const BACKUP_WRAP = '787-vault-backup-v1';

/** Son kayıt / yükleme ile editörün karşılaştırma tabanı (kaydedilmemiş değişiklik uyarısı) */
let editorBaselineTitle = '';
let editorBaselineContent = '';

function syncEditorBaseline() {
    editorBaselineTitle = noteTitle ? noteTitle.value : '';
    editorBaselineContent = noteContent ? noteContent.value : '';
}

function hasUnsavedNoteChanges() {
    if (!Session.isUnlocked() || !activeNoteId) return false;
    if (!noteTitle || !noteContent) return false;
    return noteTitle.value !== editorBaselineTitle || noteContent.value !== editorBaselineContent;
}

// ============================================================
// MEMORY / ENCODING UTILITIES
// ============================================================

function zeroFill(u8) {
    if (u8 && u8.fill) u8.fill(0);
}

function b64encode(buf) {
    const bytes = new Uint8Array(buf);
    const chunk = 8192;
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

function b64decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function stableStringify(value) {
    if (value === null || value === undefined) return JSON.stringify(value);
    const t = typeof value;
    if (t === 'number' || t === 'boolean' || t === 'bigint') return JSON.stringify(value);
    if (t === 'string') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
    if (t === 'object') {
        const keys = Object.keys(value).sort();
        return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
    }
    return JSON.stringify(value);
}

function integritySnapshot(v) {
    return {
        vaultFormatVersion: v.vaultFormatVersion ?? 1,
        salt: v.salt,
        kdf: v.kdf ?? null,
        kdfParams: v.kdfParams ?? null,
        verifier: v.verifier,
        notes: v.notes,
    };
}

async function importRawKeyMaterial(materialB64) {
    const raw = b64decode(materialB64);
    try {
        const aes = raw.slice(0, 32);
        const hm = raw.slice(32, 64);
        const master = await crypto.subtle.importKey('raw', aes, 'AES-GCM', false, ['encrypt', 'decrypt']);
        const hk = await crypto.subtle.importKey(
            'raw',
            hm,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign', 'verify']
        );
        return { master, hmacKey: hk };
    } finally {
        zeroFill(raw);
    }
}

// ============================================================
// KDF — legacy PBKDF2 + scrypt (main process)
// ============================================================

async function deriveSessionPbkdf2(password) {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    const mk = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: encoder.encode(currentVault.salt), iterations: 250000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    const hk = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: encoder.encode(currentVault.salt + '_hmac'), iterations: 100000, hash: 'SHA-256' },
        baseKey,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify']
    );
    Session.setKeys(mk, hk);
}

async function deriveSessionScrypt(password) {
    const res = await window.api.deriveScryptKeyMaterial(password, currentVault.salt);
    if (!res || !res.ok) throw new Error('KEY_DERIVATION_FAILED');
    const { master, hmacKey } = await importRawKeyMaterial(res.materialB64);
    Session.setKeys(master, hmacKey);
}

async function deriveKeysForPassword(password, salt, kdf) {
    if (kdf === 'scrypt-v1') {
        const res = await window.api.deriveScryptKeyMaterial(password, salt);
        if (!res || !res.ok) throw new Error('KEY_DERIVATION_FAILED');
        return importRawKeyMaterial(res.materialB64);
    }
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    const mk = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: encoder.encode(salt), iterations: 250000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    const hk = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: encoder.encode(salt + '_hmac'), iterations: 100000, hash: 'SHA-256' },
        baseKey,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify']
    );
    return { master: mk, hmacKey: hk };
}

// ============================================================
// AES-GCM (unique IV per encryption; auth tag validated by subtle.decrypt)
// ============================================================

async function encryptBlob(text, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
    return { content: b64encode(encrypted), iv: b64encode(iv) };
}

async function decryptBlob(data, key) {
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64decode(data.iv) },
        key,
        b64decode(data.content)
    );
    return new TextDecoder().decode(decrypted);
}

async function encryptWithSession(text) {
    return encryptBlob(text, Session.getMaster());
}

async function decryptWithSession(data) {
    return decryptBlob(data, Session.getMaster());
}

// ============================================================
// HMAC-SHA256 vault integrity (canonical payload)
// ============================================================

async function signVaultNotes(notes, hk) {
    const snap = integritySnapshot({ ...currentVault, notes });
    const payload = new TextEncoder().encode(stableStringify(snap));
    const signature = await crypto.subtle.sign('HMAC', hk, payload);
    return b64encode(signature);
}

async function verifyVaultIntegrity(vault) {
    if (!vault.hmac) return true;
    const hk = Session.getHmac();
    if (!hk) return false;
    let payload;
    if (vault.hmacVersion === 2 || (vault.vaultFormatVersion && vault.vaultFormatVersion >= 2)) {
        payload = new TextEncoder().encode(stableStringify(integritySnapshot(vault)));
    } else {
        payload = new TextEncoder().encode(JSON.stringify(vault.notes));
    }
    return crypto.subtle.verify('HMAC', hk, b64decode(vault.hmac), payload);
}

async function persistVault() {
    currentVault.hmac = await signVaultNotes(currentVault.notes, Session.getHmac());
    currentVault.hmacVersion = 2;
    currentVault.vaultFormatVersion = 2;
    const ok = await verifyVaultIntegrity(currentVault);
    if (!ok) {
        showToast('Bütünlük doğrulaması başarısız.', 'error');
        return false;
    }
    const res = await window.api.saveVault(currentVault);
    if (res && res.error) {
        showToast('Kayıt başarısız.', 'error');
        return false;
    }
    return true;
}

// ============================================================
// KDF MIGRATION (PBKDF2 → scrypt, new salt, re-wrap)
// ============================================================

async function migrateLegacyToScrypt(password) {
    if (currentVault.kdf === 'scrypt-v1') return;

    const vaultSnapshot = {
        salt: currentVault.salt,
        notes: currentVault.notes,
        verifier: currentVault.verifier,
        hmac: currentVault.hmac,
        kdf: currentVault.kdf,
        kdfParams: currentVault.kdfParams,
        vaultFormatVersion: currentVault.vaultFormatVersion,
        hmacVersion: currentVault.hmacVersion,
    };
    const oldMaster = Session.getMaster();
    const oldHmac = Session.getHmac();

    try {
        const plainNotes = [];
        for (const n of currentVault.notes) {
            plainNotes.push({
                id: n.id,
                titleText: await decryptBlob(n.title, oldMaster),
                contentText: await decryptBlob(n.content, oldMaster),
            });
        }

        const newSalt = await window.api.generateSalt();
        const res = await window.api.deriveScryptKeyMaterial(password, newSalt);
        if (!res || !res.ok) throw new Error('KEY_DERIVATION_FAILED');
        const { master: newMaster, hmacKey: newHmac } = await importRawKeyMaterial(res.materialB64);

        const rotated = [];
        for (const p of plainNotes) {
            rotated.push({
                id: p.id,
                title: await encryptBlob(p.titleText, newMaster),
                content: await encryptBlob(p.contentText, newMaster),
            });
        }

        currentVault.salt = newSalt;
        currentVault.notes = rotated;
        currentVault.kdf = 'scrypt-v1';
        currentVault.kdfParams = { N: 131072, r: 8, p: 1 };
        currentVault.vaultFormatVersion = 2;
        currentVault.hmacVersion = 2;
        currentVault.verifier = await encryptBlob('VAULT_VERIFIED', newMaster);
        currentVault.hmac = await signVaultNotes(rotated, newHmac);
        Session.setKeys(newMaster, newHmac);

        const ok = await verifyVaultIntegrity(currentVault);
        if (!ok) throw new Error('INTEGRITY_FAIL');

        const saveRes = await window.api.saveVault(currentVault);
        if (saveRes && saveRes.error) throw new Error('SAVE_FAIL');

        showToast('Kasa scrypt KDF ile güncellendi.', 'success');
    } catch (e) {
        Object.assign(currentVault, vaultSnapshot);
        Session.setKeys(oldMaster, oldHmac);
        if (e && e.message === 'SAVE_FAIL') {
            showToast('KDF güncellemesi diske yazılamadı. Eski biçem korunuyor.', 'error');
            return;
        }
        throw e;
    }
}

// ============================================================
// LAZY NOTE ACCESS
// ============================================================

async function getNoteTitleCached(note) {
    if (decryptedTitleCache.has(note.id)) return decryptedTitleCache.get(note.id);
    const title = await decryptWithSession(note.title);
    decryptedTitleCache.set(note.id, title);
    return title;
}

function evictSensitiveCaches() {
    decryptedTitleCache.clear();
    noteTitle.value = '';
    noteContent.value = '';
    syncEditorBaseline();
}

function resetNoteSearch() {
    searchResultIds = null;
    if (noteSearchInput) noteSearchInput.value = '';
}

async function applyNoteSearch() {
    if (!noteSearchInput || !Session.isUnlocked()) return;
    const q = noteSearchInput.value.trim().toLowerCase();
    if (!q) {
        searchResultIds = null;
        renderNotesList();
        return;
    }
    const scanContent = noteSearchContent && noteSearchContent.checked;
    const ids = new Set();
    for (const n of currentVault.notes) {
        const title = await getNoteTitleCached(n);
        if (title.toLowerCase().includes(q)) {
            ids.add(n.id);
            continue;
        }
        if (scanContent) {
            const body = await decryptWithSession(n.content);
            if (body.toLowerCase().includes(q)) ids.add(n.id);
        }
    }
    searchResultIds = ids;
    renderNotesList();
}

function scheduleSearch() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
        applyNoteSearch().catch(() => renderNotesList());
    }, 180);
}

// ============================================================
// YEDEK (oturum anahtarıyla şifreli dosya)
// ============================================================

async function exportNotesBackup() {
    if (!Session.isUnlocked()) return;
    try {
        const notesPlain = [];
        for (const n of currentVault.notes) {
            notesPlain.push({
                id: n.id,
                title: await decryptWithSession(n.title),
                content: await decryptWithSession(n.content),
            });
        }
        const inner = JSON.stringify({
            format: BACKUP_WRAP,
            exportedAt: new Date().toISOString(),
            notes: notesPlain,
        });
        const enc = await encryptWithSession(inner);
        const wrapper = JSON.stringify({
            format: BACKUP_WRAP,
            encrypted: true,
            iv: enc.iv,
            content: enc.content,
        });
        const res = await window.api.saveBackup(wrapper);
        if (res && res.canceled) return;
        if (res && res.error) {
            showToast('Yedek kaydedilemedi.', 'error');
            return;
        }
        showToast('Yedek kaydedildi.', 'success');
    } catch {
        showToast('Yedek oluşturulamadı.', 'error');
    }
}

async function importNotesBackup() {
    if (!Session.isUnlocked()) return;
    try {
        const res = await window.api.openBackup();
        if (res && res.canceled) return;
        if (res && res.error) {
            showToast('Dosya okunamadı.', 'error');
            return;
        }
        let parsed;
        try {
            parsed = JSON.parse(res.content);
        } catch {
            showToast('Geçersiz dosya.', 'error');
            return;
        }
        if (!parsed.encrypted || !parsed.iv || !parsed.content || parsed.format !== BACKUP_WRAP) {
            showToast('Geçersiz veya uyumsuz yedek.', 'error');
            return;
        }
        let innerJson;
        try {
            innerJson = await decryptWithSession({ iv: parsed.iv, content: parsed.content });
        } catch {
            showToast('Yedek bu kasa anahtarıyla çözülemedi.', 'error');
            return;
        }
        let inner;
        try {
            inner = JSON.parse(innerJson);
        } catch {
            showToast('Yedek verisi bozuk.', 'error');
            return;
        }
        if (!inner.notes || !Array.isArray(inner.notes)) {
            showToast('Yedek içeriği geçersiz.', 'error');
            return;
        }
        for (const item of inner.notes) {
            if (!item.id || typeof item.title !== 'string' || typeof item.content !== 'string') continue;
            const titleEnc = await encryptWithSession(item.title);
            const contentEnc = await encryptWithSession(item.content);
            const idx = currentVault.notes.findIndex((n) => n.id === item.id);
            if (idx >= 0) currentVault.notes[idx] = { id: item.id, title: titleEnc, content: contentEnc };
            else currentVault.notes.push({ id: item.id, title: titleEnc, content: contentEnc });
        }
        decryptedTitleCache.clear();
        const ok = await persistVault();
        if (ok) {
            showToast('Yedek içe aktarıldı.', 'success');
            updateMetrics();
            scheduleSearch();
            renderNotesList();
        }
    } catch {
        showToast('İçe aktarma başarısız.', 'error');
    }
}

// ============================================================
// CORE ACTIONS
// ============================================================

async function init() {
    const vault = await window.api.loadVault();
    if (vault.error) {
        $('lock-msg').textContent = 'Kasa dosyası okunamadı.';
        maybeShowFirstRunWelcome();
        return;
    }
    if (vault.salt) {
        currentVault = {
            notes: vault.notes || [],
            salt: vault.salt,
            verifier: vault.verifier,
            hmac: vault.hmac,
            kdf: vault.kdf || null,
            kdfParams: vault.kdfParams || null,
            vaultFormatVersion: vault.vaultFormatVersion || 1,
            hmacVersion: vault.hmacVersion || 1,
        };
        $('lock-msg').textContent = 'Kasa mevcut. Sisteme giriş yapın.';
    } else {
        $('lock-msg').textContent = 'Yeni bir 787 Kasası oluşturun.';
        currentVault.salt = await window.api.generateSalt();
        currentVault.kdf = 'scrypt-v1';
        currentVault.kdfParams = { N: 131072, r: 8, p: 1 };
        currentVault.vaultFormatVersion = 2;
        currentVault.hmacVersion = 2;
    }
    maybeShowFirstRunWelcome();
}

function usesScryptKdf() {
    return currentVault.kdf === 'scrypt-v1';
}

async function handleUnlock() {
    const pwd = passwordInput.value;
    if (!pwd) {
        lockError.textContent = 'Şifre gerekli.';
        return;
    }

    unlockBtn.disabled = true;
    $('unlock-btn-text').textContent = 'Açılıyor…';
    lockError.textContent = '';

    try {
        const isNew = !currentVault.verifier;

        if (isNew) {
            await deriveSessionScrypt(pwd);
            currentVault.verifier = await encryptWithSession('VAULT_VERIFIED');
            currentVault.notes = currentVault.notes || [];
            currentVault.kdf = 'scrypt-v1';
            currentVault.kdfParams = { N: 131072, r: 8, p: 1 };
            currentVault.vaultFormatVersion = 2;
            currentVault.hmacVersion = 2;
            currentVault.hmac = await signVaultNotes(currentVault.notes, Session.getHmac());
            if (!(await verifyVaultIntegrity(currentVault))) throw new Error('INTEGRITY_FAIL');
            const saveRes = await window.api.saveVault(currentVault);
            if (saveRes && saveRes.error) throw new Error('SAVE_FAIL');
        } else {
            if (usesScryptKdf()) {
                await deriveSessionScrypt(pwd);
            } else {
                await deriveSessionPbkdf2(pwd);
            }

            const check = await decryptWithSession(currentVault.verifier);
            if (check !== 'VAULT_VERIFIED') throw new Error('AUTH_FAIL');

            if (!(await verifyVaultIntegrity(currentVault))) throw new Error('INTEGRITY_FAIL');

            if (!usesScryptKdf()) {
                await migrateLegacyToScrypt(pwd);
            }
        }

        passwordInput.value = '';
        lockScreen.classList.add('hidden');
        mainPanel.classList.remove('hidden');
        showToast('Kasa açıldı.', 'success');
        updateMetrics();
        resetNoteSearch();
        renderNotesList();
        switchView('hub');
        resetInactivityTimer();
    } catch {
        lockError.textContent = 'Hatalı şifre veya kasa bütünlüğü bozuk.';
        Session.clear();
    } finally {
        unlockBtn.disabled = false;
        $('unlock-btn-text').textContent = 'Kilidi aç';
    }
}

async function handleSaveNote() {
    if (!activeNoteId || !Session.isUnlocked()) return;
    const titleText = noteTitle.value || 'Adsız Not';
    const title = await encryptWithSession(titleText);
    const content = await encryptWithSession(noteContent.value);

    const idx = currentVault.notes.findIndex((n) => n.id === activeNoteId);
    if (idx === -1) currentVault.notes.push({ id: activeNoteId, title, content });
    else currentVault.notes[idx] = { id: activeNoteId, title, content };

    decryptedTitleCache.delete(activeNoteId);
    const ok = await persistVault();
    if (ok) {
        syncEditorBaseline();
        showToast('Kaydedildi.', 'success');
        updateMetrics();
        await applyNoteSearch();
    }
}

async function handleDeleteNote() {
    if (!activeNoteId) return;
    currentVault.notes = currentVault.notes.filter((n) => n.id !== activeNoteId);
    decryptedTitleCache.delete(activeNoteId);
    const ok = await persistVault();
    if (!ok) return;
    activeNoteId = null;
    noteTitle.value = '';
    noteContent.value = '';
    syncEditorBaseline();
    showToast('Not silindi.');
    updateMetrics();
    await applyNoteSearch();
    switchView('hub');
}

async function renderNotesList() {
    while (notesList.firstChild) notesList.removeChild(notesList.firstChild);

    const visible =
        searchResultIds === null
            ? currentVault.notes
            : currentVault.notes.filter((n) => searchResultIds.has(n.id));

    for (const note of visible) {
        const div = document.createElement('div');
        div.className = 'note-item' + (activeNoteId === note.id ? ' active' : '');

        const icon = document.createElement('i');
        icon.className = 'ph ph-file-text';

        const h4 = document.createElement('h4');
        h4.textContent = '…';

        div.appendChild(icon);
        div.appendChild(h4);

        div.onclick = () => {
            activeNoteId = note.id;
            openNote(note);
            switchView('notes');
        };

        notesList.appendChild(div);

        (async () => {
            try {
                if (!Session.isUnlocked()) return;
                const title = await getNoteTitleCached(note);
                h4.textContent = title;
            } catch {
                h4.textContent = '—';
            }
        })();
    }
}

async function openNote(note) {
    try {
        noteTitle.value = await decryptWithSession(note.title);
        noteContent.value = await decryptWithSession(note.content);
        syncEditorBaseline();
        renderNotesList();
    } catch {
        showToast('Veri okunamadı.', 'error');
    }
}

function updateMetrics() {
    statCount.textContent = String(currentVault.notes.length);
}

// ============================================================
// PASSWORD ROTATION
// ============================================================

async function handlePasswordChange() {
    const oldP = oldPasswordInput.value;
    const newP = newPasswordInput.value;
    if (!oldP || !newP) {
        changePwdError.textContent = 'Alanlar boş bırakılamaz.';
        return;
    }

    changePasswordBtn.disabled = true;
    $('change-btn-text').textContent = 'Güncelleniyor…';
    changePwdError.textContent = '';

    try {
        const kdf = currentVault.kdf === 'scrypt-v1' ? 'scrypt-v1' : 'pbkdf2';
        const { master: oldMaster, hmacKey: oldHmac } = await deriveKeysForPassword(oldP, currentVault.salt, kdf);

        const test = await decryptBlob(currentVault.verifier, oldMaster);
        if (test !== 'VAULT_VERIFIED') throw new Error('AUTH_FAIL');

        const tempNotes = [];
        for (const n of currentVault.notes) {
            tempNotes.push({
                id: n.id,
                titleText: await decryptBlob(n.title, oldMaster),
                contentText: await decryptBlob(n.content, oldMaster),
            });
        }

        const newSalt = await window.api.generateSalt();
        const res = await window.api.deriveScryptKeyMaterial(newP, newSalt);
        if (!res || !res.ok) throw new Error('KEY_DERIVATION_FAILED');
        const { master: newMaster, hmacKey: newHmac } = await importRawKeyMaterial(res.materialB64);

        const rotatedNotes = [];
        for (const tn of tempNotes) {
            rotatedNotes.push({
                id: tn.id,
                title: await encryptBlob(tn.titleText, newMaster),
                content: await encryptBlob(tn.contentText, newMaster),
            });
        }

        currentVault.salt = newSalt;
        currentVault.notes = rotatedNotes;
        currentVault.kdf = 'scrypt-v1';
        currentVault.kdfParams = { N: 131072, r: 8, p: 1 };
        currentVault.vaultFormatVersion = 2;
        currentVault.hmacVersion = 2;
        currentVault.verifier = await encryptBlob('VAULT_VERIFIED', newMaster);
        currentVault.hmac = await signVaultNotes(rotatedNotes, newHmac);

        /* verifyVaultIntegrity Session HMAC kullanır; önce yeni anahtarları bağla */
        Session.setKeys(newMaster, newHmac);

        const ok = await verifyVaultIntegrity(currentVault);
        if (!ok) throw new Error('INTEGRITY_FAIL');

        const saveRes = await window.api.saveVault(currentVault);
        if (saveRes && saveRes.error) throw new Error('SAVE_FAIL');

        decryptedTitleCache.clear();

        oldPasswordInput.value = '';
        newPasswordInput.value = '';
        showToast('Şifre güncellendi.', 'success');
        switchView('hub');
        renderNotesList();
    } catch {
        changePwdError.textContent = 'İşlem başarısız. Şifreleri kontrol edin.';
    } finally {
        changePasswordBtn.disabled = false;
        $('change-btn-text').textContent = 'Şifreyi güncelle';
    }
}

// ============================================================
// TÜM VERİLERİ SİL (şifre doğrulaması zorunlu)
// ============================================================

async function handleWipeAllData() {
    if (!Session.isUnlocked() || !wipePasswordInput || !wipeAllBtn) return;

    const pwd = wipePasswordInput.value;
    if (!pwd) {
        if (wipeError) wipeError.textContent = 'Onay için şifre gerekli.';
        return;
    }

    const sure = window.confirm(
        'Tüm notlar ve kasa dosyası bu cihazdan silinecek. Bu işlem geri alınamaz. Devam edilsin mi?'
    );
    if (!sure) return;

    wipeAllBtn.disabled = true;
    if (wipeError) wipeError.textContent = '';

    try {
        const kdf = currentVault.kdf === 'scrypt-v1' ? 'scrypt-v1' : 'pbkdf2';
        const { master } = await deriveKeysForPassword(pwd, currentVault.salt, kdf);
        const test = await decryptBlob(currentVault.verifier, master);
        if (test !== 'VAULT_VERIFIED') throw new Error('AUTH_FAIL');

        const delRes = await window.api.secureDelete();
        if (delRes && delRes.error) throw new Error('DELETE_FAIL');

        clearTimeout(inactivityTimer);
        clearTimeout(searchTimer);
        Session.clear();
        decryptedTitleCache.clear();
        resetNoteSearch();
        activeNoteId = null;
        noteTitle.value = '';
        noteContent.value = '';
        syncEditorBaseline();

        currentVault = {
            notes: [],
            salt: await window.api.generateSalt(),
            verifier: null,
            hmac: null,
            kdf: 'scrypt-v1',
            kdfParams: { N: 131072, r: 8, p: 1 },
            vaultFormatVersion: 2,
            hmacVersion: 2,
        };

        wipePasswordInput.value = '';
        if (oldPasswordInput) oldPasswordInput.value = '';
        if (newPasswordInput) newPasswordInput.value = '';

        mainPanel.classList.add('hidden');
        lockScreen.classList.remove('hidden');
        if ($('lock-msg')) {
            $('lock-msg').textContent =
                'Tüm veriler silindi. Yeni kasa için bir ana şifre belirleyip kilidi açın.';
        }
        if (passwordInput) {
            passwordInput.value = '';
            passwordInput.focus();
        }
        showToast('Tüm veriler silindi.', 'success');
    } catch {
        if (wipeError) wipeError.textContent = 'Şifre yanlış veya silme başarısız.';
    } finally {
        wipeAllBtn.disabled = false;
    }
}

// ============================================================
// NAVIGATION
// ============================================================

async function createNewNote() {
    activeNoteId = await window.api.generateSecureId();
    noteTitle.value = '';
    noteContent.value = '';
    syncEditorBaseline();
    switchView('notes');
    noteTitle.focus();
}

function switchView(view) {
    currentView = view;
    [navHub, navSecurity].forEach((t) => t.classList.remove('active'));
    [hubView, noteView, securityView].forEach((v) => v.classList.add('hidden'));

    if (view === 'hub') {
        navHub.classList.add('active');
        hubView.classList.remove('hidden');
    } else if (view === 'notes') {
        noteView.classList.remove('hidden');
    } else {
        navSecurity.classList.add('active');
        securityView.classList.remove('hidden');
    }
}

function showToast(msg, type = 'info') {
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    const ic = document.createElement('i');
    ic.className =
        type === 'success' ? 'ph-fill ph-check-circle' : type === 'error' ? 'ph-fill ph-warning-circle' : 'ph-fill ph-info';
    const span = document.createElement('span');
    span.textContent = String(msg);
    t.appendChild(ic);
    t.appendChild(span);
    toastContainer.appendChild(t);
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transform = 'translateY(20px)';
        setTimeout(() => t.remove(), 400);
    }, 4000);
}

function lockVault() {
    clearTimeout(inactivityTimer);
    clearTimeout(searchTimer);
    Session.clear();
    resetNoteSearch();
    activeNoteId = null;
    evictSensitiveCaches();
    mainPanel.classList.add('hidden');
    lockScreen.classList.remove('hidden');
}

function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    if (Session.isUnlocked()) inactivityTimer = setTimeout(lockVault, INACTIVITY_LIMIT);
}

function onWindowBlur() {
    if (!Session.isUnlocked()) return;
    /* Not alanını temizleme: native onay penceresi veya hızlı odak kaybında metin kayboluyordu */
    decryptedTitleCache.clear();
}

/**
 * Pencere arka plana alınınca not başlık önbelleğini boşaltır.
 * Not içeriğini silmiyoruz: minimize / Alt+Tab sonrası yazı ve odak bozuluyordu.
 */
function onVisibilityChange() {
    if (!Session.isUnlocked()) return;
    if (document.visibilityState === 'hidden') {
        decryptedTitleCache.clear();
        return;
    }
    restoreFocusAfterAppForeground();
}

function restoreFocusAfterAppForeground() {
    if (!Session.isUnlocked() || mainPanel.classList.contains('hidden')) return;
    requestAnimationFrame(() => {
        const ae = document.activeElement;
        if (
            ae &&
            ae !== document.body &&
            (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.tagName === 'BUTTON')
        ) {
            return;
        }
        if (!noteView.classList.contains('hidden') && activeNoteId && noteContent) {
            noteContent.focus({ preventScroll: true });
            return;
        }
        if (!hubView.classList.contains('hidden') && noteSearchInput) {
            noteSearchInput.focus({ preventScroll: true });
        }
    });
}

// ============================================================
// İLK AÇILIŞ BİLGİLENDİRME
// ============================================================

const WELCOME_DISMISSED_KEY = '787-vault-welcome-v1-dismissed';

function dismissFirstRunWelcome() {
    const overlay = $('welcome-overlay');
    try {
        localStorage.setItem(WELCOME_DISMISSED_KEY, '1');
    } catch (_) {}
    if (overlay) overlay.classList.add('hidden');
    if (passwordInput) passwordInput.focus();
}

function maybeShowFirstRunWelcome() {
    let dismissed = false;
    try {
        dismissed = localStorage.getItem(WELCOME_DISMISSED_KEY) === '1';
    } catch (_) {
        return;
    }
    if (dismissed) return;
    const overlay = $('welcome-overlay');
    const btn = $('welcome-dismiss');
    if (!overlay || !btn) return;
    overlay.classList.remove('hidden');
    btn.onclick = dismissFirstRunWelcome;
    setTimeout(() => btn.focus(), 50);
}

function isAccelKey(e) {
    return e.ctrlKey || e.metaKey;
}

// ============================================================
// EVENTS
// ============================================================

unlockBtn.onclick = handleUnlock;
navHub.onclick = () => switchView('hub');
navSecurity.onclick = () => switchView('security');

saveBtn.onclick = handleSaveNote;
deleteBtn.onclick = handleDeleteNote;
newNoteBtn.onclick = () => {
    createNewNote().catch(() => showToast('Yeni not oluşturulamadı.', 'error'));
};
lockAppBtn.onclick = lockVault;
changePasswordBtn.onclick = handlePasswordChange;
if (wipeAllBtn) wipeAllBtn.onclick = handleWipeAllData;

if (noteSearchInput) {
    noteSearchInput.addEventListener('input', scheduleSearch);
}
if (noteSearchContent) {
    noteSearchContent.addEventListener('change', () => {
        clearTimeout(searchTimer);
        applyNoteSearch().catch(() => renderNotesList());
    });
}
if (backupExportBtn) backupExportBtn.onclick = exportNotesBackup;
if (backupImportBtn) backupImportBtn.onclick = importNotesBackup;

/* mousemove her pikselde tetiklenmesin — ana iş parçacığını rahatlatır */
let inactivityMoveRaf = null;
document.addEventListener(
    'mousemove',
    () => {
        if (inactivityMoveRaf != null) return;
        inactivityMoveRaf = requestAnimationFrame(() => {
            inactivityMoveRaf = null;
            resetInactivityTimer();
        });
    },
    { passive: true }
);
['keydown', 'click', 'wheel', 'touchstart'].forEach((e) =>
    document.addEventListener(e, resetInactivityTimer, { passive: true })
);

document.addEventListener('visibilitychange', onVisibilityChange);
window.addEventListener('blur', onWindowBlur);
window.addEventListener('focus', () => {
    if (Session.isUnlocked()) restoreFocusAfterAppForeground();
});

document.addEventListener(
    'keydown',
    (e) => {
        const welcome = $('welcome-overlay');
        if (welcome && !welcome.classList.contains('hidden')) {
            if (e.key === 'Escape') {
                e.preventDefault();
                dismissFirstRunWelcome();
            }
            return;
        }

        const quitOv = $('quit-confirm-overlay');
        if (quitOv && !quitOv.classList.contains('hidden')) {
            if (e.key === 'Escape') {
                e.preventDefault();
                quitOv.classList.add('hidden');
            }
            return;
        }

        if (!Session.isUnlocked() || !mainPanel || mainPanel.classList.contains('hidden')) return;
        if (!isAccelKey(e) || e.altKey) return;

        const ch = e.key.length === 1 ? e.key.toLowerCase() : '';
        if (ch === 's') {
            e.preventDefault();
            handleSaveNote();
            resetInactivityTimer();
            return;
        }
        if (ch === 'n') {
            e.preventDefault();
            createNewNote().catch(() => showToast('Yeni not oluşturulamadı.', 'error'));
            resetInactivityTimer();
            return;
        }
        if (ch === 'f') {
            e.preventDefault();
            switchView('notes');
            if (noteSearchInput) {
                noteSearchInput.focus();
                try {
                    noteSearchInput.select();
                } catch (_) {}
            }
            resetInactivityTimer();
            return;
        }
        if (ch === 'l') {
            e.preventDefault();
            lockVault();
        }
    },
    true
);

if (window.api.onBeforeClose) {
    window.api.onBeforeClose(() => {
        if (!hasUnsavedNoteChanges()) {
            window.api.confirmQuit();
            return;
        }
        showUnsavedQuitModal();
    });
}

function showUnsavedQuitModal() {
    const overlay = $('quit-confirm-overlay');
    if (!overlay) {
        window.api.confirmQuit();
        return;
    }
    overlay.classList.remove('hidden');
    const saveBtn = $('quit-save-btn');
    const discardBtn = $('quit-discard-btn');
    const cancelBtn = $('quit-cancel-btn');

    const close = () => {
        overlay.classList.add('hidden');
        saveBtn.onclick = null;
        discardBtn.onclick = null;
        cancelBtn.onclick = null;
    };

    saveBtn.onclick = async () => {
        await handleSaveNote();
        close();
        if (!hasUnsavedNoteChanges()) {
            window.api.confirmQuit();
        }
    };
    discardBtn.onclick = () => {
        close();
        window.api.confirmQuit();
    };
    cancelBtn.onclick = () => close();
}

init();
