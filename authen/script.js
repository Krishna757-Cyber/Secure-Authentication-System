/**
 * script.js – Secure Authentication System
 * Mirrors the C implementation in the browser:
 *   - XOR encryption (same key: 0x5A)
 *   - localStorage credential store (simulating binary file)
 *   - Intrusion detection (lockout after 3 failed attempts)
 *   - Role-based access control (user / admin)
 *   - Security event logging
 *   - Password masking, attempt tracking
 */

'use strict';

/* ════════════════════════════════════════════════════════
 *  CONSTANTS  (mirrors functions.h)
 * ════════════════════════════════════════════════════════ */
const XOR_KEY           = 0x5A;
const MAX_LOGIN_ATTEMPTS = 3;
const STORE_KEY          = 'sas_credentials';   // localStorage key
const LOG_KEY            = 'sas_security_log';

const ROLE_USER  = 0;
const ROLE_ADMIN = 1;

const AUTH_SUCCESS = 'AUTH_SUCCESS';
const AUTH_FAIL    = 'AUTH_FAIL';
const AUTH_LOCKED  = 'AUTH_LOCKED';
const REG_SUCCESS  = 'REG_SUCCESS';
const REG_EXISTS   = 'REG_EXISTS';


/* ════════════════════════════════════════════════════════
 *  ENCRYPTION  (XOR cipher – symmetric)
 * ════════════════════════════════════════════════════════ */

/**
 * xorProcess – Applies XOR with XOR_KEY to every character code.
 * Because XOR is its own inverse, this handles both encrypt/decrypt.
 * Returns a hex-encoded string (safe for storage / display).
 */
function xorEncrypt(plaintext) {
  let result = '';
  for (let i = 0; i < plaintext.length; i++) {
    const enc = (plaintext.charCodeAt(i) ^ XOR_KEY).toString(16).padStart(2, '0');
    result += enc;
  }
  return result;
}

function xorDecrypt(hexStr) {
  let result = '';
  for (let i = 0; i < hexStr.length; i += 2) {
    const byte = parseInt(hexStr.substr(i, 2), 16);
    result += String.fromCharCode(byte ^ XOR_KEY);
  }
  return result;
}


/* ════════════════════════════════════════════════════════
 *  STORAGE  (localStorage ↔ JSON  ≈  credentials.dat)
 * ════════════════════════════════════════════════════════ */

function loadUsers() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY)) || [];
  } catch { return []; }
}

function saveUsers(users) {
  localStorage.setItem(STORE_KEY, JSON.stringify(users));
}

function findUser(users, username) {
  return users.findIndex(u => u.username === username);
}


/* ════════════════════════════════════════════════════════
 *  LOGGING  (security.log equivalent)
 * ════════════════════════════════════════════════════════ */

function logEvent(eventType, username, detail) {
  const logs = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
  logs.push({
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
    eventType,
    username,
    detail
  });
  localStorage.setItem(LOG_KEY, JSON.stringify(logs));
}

function getLogs() {
  return JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
}


/* ════════════════════════════════════════════════════════
 *  REGISTRATION
 * ════════════════════════════════════════════════════════ */

function registerUser(username, password, role = ROLE_USER) {
  const users = loadUsers();
  if (findUser(users, username) !== -1) {
    logEvent('REG_FAIL', username, 'Username already exists');
    return REG_EXISTS;
  }

  users.push({
    username,
    encPassword:     xorEncrypt(password),
    role,
    failedAttempts:  0,
    isLocked:        false
  });

  saveUsers(users);
  logEvent('REGISTER', username, role === ROLE_ADMIN ? 'Admin account created' : 'User account created');
  return REG_SUCCESS;
}


/* ════════════════════════════════════════════════════════
 *  AUTHENTICATION
 * ════════════════════════════════════════════════════════ */

function authenticateUser(username, password) {
  const users = loadUsers();
  const idx   = findUser(users, username);

  if (idx === -1) {
    logEvent('LOGIN_FAIL', username, 'Username not found');
    return { code: AUTH_FAIL };
  }

  if (users[idx].isLocked) {
    logEvent('LOGIN_BLOCKED', username, 'Account locked');
    return { code: AUTH_LOCKED, username };
  }

  const decrypted = xorDecrypt(users[idx].encPassword);

  if (decrypted === password) {
    users[idx].failedAttempts = 0;
    saveUsers(users);
    logEvent('LOGIN_OK', username, users[idx].role === ROLE_ADMIN ? 'Admin login' : 'User login');
    return {
      code:     AUTH_SUCCESS,
      username: users[idx].username,
      role:     users[idx].role
    };
  }

  // Wrong password
  users[idx].failedAttempts++;
  if (users[idx].failedAttempts >= MAX_LOGIN_ATTEMPTS) {
    users[idx].isLocked = true;
    saveUsers(users);
    logEvent('IDS_ALERT', username, 'BRUTE-FORCE DETECTED – Account locked');
    return { code: AUTH_LOCKED, username, brute: true };
  }

  saveUsers(users);
  logEvent('LOGIN_FAIL', username, `Wrong password (attempt ${users[idx].failedAttempts}/${MAX_LOGIN_ATTEMPTS})`);
  return {
    code:     AUTH_FAIL,
    attempts: users[idx].failedAttempts
  };
}

function getAttemptCount(username) {
  const users = loadUsers();
  const idx   = findUser(users, username);
  return idx !== -1 ? users[idx].failedAttempts : 0;
}


/* ════════════════════════════════════════════════════════
 *  PASSWORD RESET  (admin only)
 * ════════════════════════════════════════════════════════ */

function resetPassword(adminUsername, targetUsername, newPassword) {
  const users = loadUsers();
  const idx   = findUser(users, targetUsername);
  if (idx === -1) return false;

  users[idx].encPassword    = xorEncrypt(newPassword);
  users[idx].failedAttempts = 0;
  users[idx].isLocked       = false;
  saveUsers(users);
  logEvent('PWD_RESET', targetUsername, `Password reset by admin [${adminUsername}]`);
  return true;
}

function unlockAccount(adminUsername, targetUsername) {
  const users = loadUsers();
  const idx   = findUser(users, targetUsername);
  if (idx === -1) return false;

  users[idx].isLocked       = false;
  users[idx].failedAttempts = 0;
  saveUsers(users);
  logEvent('UNLOCK', targetUsername, `Account unlocked by admin [${adminUsername}]`);
  return true;
}


/* ════════════════════════════════════════════════════════
 *  SESSION STATE
 * ════════════════════════════════════════════════════════ */

let session = { loggedIn: false, username: '', role: ROLE_USER };

function startSession(username, role) {
  session = { loggedIn: true, username, role };
  updateNavbar();
}

function endSession() {
  if (session.loggedIn) {
    logEvent('LOGOUT', session.username, 'User logged out');
  }
  session = { loggedIn: false, username: '', role: ROLE_USER };
  updateNavbar();
}


/* ════════════════════════════════════════════════════════
 *  MATRIX RAIN BACKGROUND
 * ════════════════════════════════════════════════════════ */

function initMatrixRain() {
  const canvas = document.getElementById('matrix-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const chars   = '01アイウエオカキクケコサシスセソタチツテトABCDEF0123456789!@#$%';
  const fontSize = 13;
  let columns   = Math.floor(canvas.width / fontSize);
  let drops     = Array(columns).fill(1);

  function draw() {
    ctx.fillStyle = 'rgba(3, 5, 8, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#00ff41';
    ctx.font      = `${fontSize}px 'Share Tech Mono', monospace`;

    drops.forEach((y, i) => {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * fontSize, y * fontSize);
      if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });

    columns = Math.floor(canvas.width / fontSize);
    if (drops.length < columns) drops.push(...Array(columns - drops.length).fill(1));
  }

  setInterval(draw, 50);
}


/* ════════════════════════════════════════════════════════
 *  UI – PAGE ROUTING
 * ════════════════════════════════════════════════════════ */

function showPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById(pageId);
  if (target) target.classList.add('active');
}


/* ════════════════════════════════════════════════════════
 *  UI – NAVBAR
 * ════════════════════════════════════════════════════════ */

function updateNavbar() {
  const navUser = document.getElementById('nav-user-info');
  const navBadge = document.getElementById('nav-username-badge');
  const logoutBtn = document.getElementById('btn-logout');

  if (session.loggedIn) {
    navUser.style.display  = 'flex';
    navBadge.textContent   = session.username + (session.role === ROLE_ADMIN ? ' [ADMIN]' : ' [USER]');
    logoutBtn.style.display = 'inline-flex';
  } else {
    navUser.style.display   = 'none';
    logoutBtn.style.display  = 'none';
  }
}


/* ════════════════════════════════════════════════════════
 *  UI – ALERTS
 * ════════════════════════════════════════════════════════ */

function showAlert(containerId, type, message) {
  const c = document.getElementById(containerId);
  if (!c) return;
  c.innerHTML = `<div class="alert alert-${type}"><span>${type === 'success' ? '✓' : type === 'error' ? '✗' : type === 'warn' ? '⚠' : 'ℹ'}</span> ${message}</div>`;
  setTimeout(() => { if (c) c.innerHTML = ''; }, 5000);
}

function clearAlert(containerId) {
  const c = document.getElementById(containerId);
  if (c) c.innerHTML = '';
}


/* ════════════════════════════════════════════════════════
 *  UI – INTRUSION MODAL
 * ════════════════════════════════════════════════════════ */

function showIntrusionAlert(username) {
  const overlay = document.getElementById('intrusion-overlay');
  document.getElementById('intrusion-username').textContent = username;
  overlay.classList.add('show');
  // Red flash effect
  document.body.style.transition = 'background 0.1s';
  document.body.style.background = 'rgba(60,0,0,0.5)';
  setTimeout(() => { document.body.style.background = ''; }, 600);
}


/* ════════════════════════════════════════════════════════
 *  UI – ATTEMPT DOTS
 * ════════════════════════════════════════════════════════ */

function updateAttemptDots(attempts) {
  document.querySelectorAll('.attempt-dot').forEach((dot, i) => {
    dot.classList.toggle('used', i < attempts);
  });
}


/* ════════════════════════════════════════════════════════
 *  UI – LOGIN FORM
 * ════════════════════════════════════════════════════════ */

function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;

  if (!username || !password) {
    showAlert('login-alert', 'warn', 'Please enter username and password.');
    return;
  }

  const result = authenticateUser(username, password);

  switch (result.code) {
    case AUTH_SUCCESS:
      clearAlert('login-alert');
      startSession(result.username, result.role);
      document.getElementById('login-username').value = '';
      document.getElementById('login-password').value = '';
      updateAttemptDots(0);
      if (result.role === ROLE_ADMIN) {
        renderAdminDashboard();
        showPage('page-admin-dashboard');
      } else {
        renderUserDashboard();
        showPage('page-user-dashboard');
      }
      break;

    case AUTH_FAIL:
      updateAttemptDots(result.attempts || 0);
      const remaining = MAX_LOGIN_ATTEMPTS - (result.attempts || 0);
      showAlert('login-alert', 'error',
        `Invalid credentials. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`);
      break;

    case AUTH_LOCKED:
      updateAttemptDots(MAX_LOGIN_ATTEMPTS);
      showAlert('login-alert', 'error', 'Account is locked. Contact administrator.');
      showIntrusionAlert(result.username);
      break;
  }
}


/* ════════════════════════════════════════════════════════
 *  UI – REGISTER FORM
 * ════════════════════════════════════════════════════════ */

function handleRegister(e) {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;
  const role     = document.querySelector('.role-option.selected')?.dataset.role === 'admin'
                   ? ROLE_ADMIN : ROLE_USER;

  if (!username || !password) {
    showAlert('reg-alert', 'warn', 'All fields are required.');
    return;
  }

  if (password.length < 6) {
    showAlert('reg-alert', 'warn', 'Password must be at least 6 characters.');
    return;
  }

  if (password !== confirm) {
    showAlert('reg-alert', 'error', 'Passwords do not match.');
    return;
  }

  const result = registerUser(username, password, role);

  if (result === REG_SUCCESS) {
    showAlert('reg-alert', 'success', 'Account created! You can now log in.');
    document.getElementById('reg-username').value = '';
    document.getElementById('reg-password').value = '';
    document.getElementById('reg-confirm').value  = '';
    document.getElementById('reg-enc-output').textContent = '—';

    // Switch to login tab
    setTimeout(() => switchTab('login'), 1500);
  } else {
    showAlert('reg-alert', 'error', `Username "${username}" is already taken.`);
  }
}


/* ════════════════════════════════════════════════════════
 *  UI – TABS
 * ════════════════════════════════════════════════════════ */

function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.getElementById('panel-login').style.display    = tab === 'login'    ? 'block' : 'none';
  document.getElementById('panel-register').style.display = tab === 'register' ? 'block' : 'none';
}


/* ════════════════════════════════════════════════════════
 *  UI – USER DASHBOARD
 * ════════════════════════════════════════════════════════ */

function renderUserDashboard() {
  document.getElementById('ud-username').textContent    = session.username;
  const ud2 = document.getElementById('ud-username2');
  if (ud2) ud2.textContent = session.username;
  const udPlain = document.getElementById('ud-plain');
  if (udPlain) udPlain.textContent = session.username;
  document.getElementById('ud-role').textContent        = 'USER';
  document.getElementById('ud-enc-show').textContent    = '—';

  const logs    = getLogs().filter(l => l.username === session.username);
  const lastLog = logs[logs.length - 1];
  document.getElementById('ud-last-login').textContent  = lastLog ? lastLog.timestamp : 'First login';
  document.getElementById('ud-login-count').textContent = logs.filter(l => l.eventType === 'LOGIN_OK').length;
}


/* ════════════════════════════════════════════════════════
 *  UI – CHANGE OWN PASSWORD
 * ════════════════════════════════════════════════════════ */

function handleChangePassword(e) {
  e.preventDefault();
  const current = document.getElementById('cp-current').value;
  const newPwd  = document.getElementById('cp-new').value;
  const confirm = document.getElementById('cp-confirm').value;

  if (newPwd.length < 6) {
    showAlert('cp-alert', 'warn', 'New password must be at least 6 characters.');
    return;
  }
  if (newPwd !== confirm) {
    showAlert('cp-alert', 'error', 'Passwords do not match.');
    return;
  }

  // Re-authenticate with current password
  const check = authenticateUser(session.username, current);
  if (check.code !== AUTH_SUCCESS) {
    showAlert('cp-alert', 'error', 'Current password is incorrect.');
    return;
  }

  resetPassword(session.username, session.username, newPwd);
  showAlert('cp-alert', 'success', 'Password updated successfully.');
  document.getElementById('cp-current').value = '';
  document.getElementById('cp-new').value     = '';
  document.getElementById('cp-confirm').value = '';
  closeModal('modal-change-password');
}


/* ════════════════════════════════════════════════════════
 *  UI – ADMIN DASHBOARD
 * ════════════════════════════════════════════════════════ */

function renderAdminDashboard() {
  const users = loadUsers();
  const locked = users.filter(u => u.isLocked).length;
  const logs   = getLogs();

  document.getElementById('ad-total-users').textContent   = users.length;
  document.getElementById('ad-locked-accounts').textContent = locked;
  document.getElementById('ad-total-logs').textContent    = logs.length;
  document.getElementById('ad-alerts').textContent        = logs.filter(l => l.eventType === 'IDS_ALERT').length;

  renderUserTable();
  renderLogViewer();
}

function renderUserTable() {
  const users = loadUsers();
  const tbody = document.getElementById('admin-user-tbody');
  if (!tbody) return;

  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${u.username}</td>
      <td><span class="badge ${u.role === ROLE_ADMIN ? 'badge-cyan' : 'badge-green'}">${u.role === ROLE_ADMIN ? 'ADMIN' : 'USER'}</span></td>
      <td>${u.encPassword.slice(0, 16)}…</td>
      <td>${u.failedAttempts}</td>
      <td><span class="badge ${u.isLocked ? 'badge-red' : 'badge-green'}">${u.isLocked ? 'LOCKED' : 'ACTIVE'}</span></td>
      <td style="display:flex;gap:6px;flex-wrap:wrap;">
        ${u.isLocked ? `<button class="btn btn-secondary" style="padding:3px 10px;font-size:0.65rem;" onclick="adminUnlock('${u.username}')">UNLOCK</button>` : ''}
        <button class="btn btn-danger" style="padding:3px 10px;font-size:0.65rem;" onclick="openResetModal('${u.username}')">RESET PWD</button>
      </td>
    </tr>
  `).join('');
}

function renderLogViewer() {
  const logs = getLogs();
  const el   = document.getElementById('log-terminal');
  if (!el) return;

  const colorMap = {
    LOGIN_OK:      'log-ok',
    REGISTER:      'log-info',
    LOGIN_FAIL:    'log-fail',
    IDS_ALERT:     'log-fail',
    LOGIN_BLOCKED: 'log-warn',
    LOGOUT:        'log-info',
    PWD_RESET:     'log-warn',
    UNLOCK:        'log-ok',
    REG_FAIL:      'log-warn',
  };

  el.innerHTML = logs.length === 0
    ? '<span class="log-prompt">No events logged yet.</span>'
    : logs.slice().reverse().map(l =>
        `<div><span class="log-prompt">[${l.timestamp}]</span> <span class="${colorMap[l.eventType] || 'log-info'}">${l.eventType.padEnd(15)}</span> <span style="color:#4d7a5a">| ${l.username.padEnd(18)}</span> | ${l.detail}</div>`
      ).join('');

  el.scrollTop = 0;
}


/* ════════════════════════════════════════════════════════
 *  UI – ADMIN ACTIONS
 * ════════════════════════════════════════════════════════ */

function adminUnlock(username) {
  if (unlockAccount(session.username, username)) {
    renderAdminDashboard();
    showAlert('admin-alert', 'success', `Account "${username}" unlocked.`);
  }
}

let resetTargetUser = '';

function openResetModal(username) {
  resetTargetUser = username;
  document.getElementById('reset-target-label').textContent = username;
  document.getElementById('reset-new-password').value = '';
  openModal('modal-reset-password');
}

function handleAdminReset(e) {
  e.preventDefault();
  const newPwd = document.getElementById('reset-new-password').value;
  if (newPwd.length < 6) {
    showAlert('reset-alert', 'warn', 'Password must be at least 6 characters.');
    return;
  }
  if (resetPassword(session.username, resetTargetUser, newPwd)) {
    showAlert('admin-alert', 'success', `Password for "${resetTargetUser}" reset.`);
    renderAdminDashboard();
    closeModal('modal-reset-password');
  }
}


/* ════════════════════════════════════════════════════════
 *  UI – MODALS
 * ════════════════════════════════════════════════════════ */

function openModal(id) {
  document.getElementById(id)?.classList.add('show');
}

function closeModal(id) {
  document.getElementById(id)?.classList.remove('show');
}


/* ════════════════════════════════════════════════════════
 *  UI – ENCRYPTION DEMO (live)
 * ════════════════════════════════════════════════════════ */

function updateEncryptionDemo(plaintext, outputId) {
  const el = document.getElementById(outputId);
  if (!el) return;
  el.textContent = plaintext.length > 0 ? xorEncrypt(plaintext) : '—';
}


/* ════════════════════════════════════════════════════════
 *  INIT
 * ════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  // Seed default admin on first run
  if (loadUsers().length === 0) {
    registerUser('admin', 'Admin@123', ROLE_ADMIN);
    registerUser('alice', 'alice123',  ROLE_USER);
    logEvent('SYSTEM', 'SYSTEM', 'Database initialised with default accounts');
  }

  initMatrixRain();
  updateNavbar();
  showPage('page-landing');

  /* ── Landing buttons ── */
  document.getElementById('btn-go-login').addEventListener('click', () => {
    showPage('page-auth');
    switchTab('login');
  });
  document.getElementById('btn-go-register').addEventListener('click', () => {
    showPage('page-auth');
    switchTab('register');
  });

  /* ── Auth tabs ── */
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  /* ── Login form ── */
  document.getElementById('form-login').addEventListener('submit', handleLogin);

  /* ── Register form ── */
  document.getElementById('form-register').addEventListener('submit', handleRegister);

  /* ── Register: live encryption preview ── */
  document.getElementById('reg-password').addEventListener('input', e => {
    updateEncryptionDemo(e.target.value, 'reg-enc-output');
  });

  /* ── Role selector ── */
  document.querySelectorAll('.role-option').forEach(opt => {
    opt.addEventListener('click', () => {
      document.querySelectorAll('.role-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
    });
  });

  /* ── Password toggle buttons ── */
  document.querySelectorAll('.toggle-pw').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.target);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? '👁' : '🙈';
    });
  });

  /* ── Logout ── */
  document.getElementById('btn-logout').addEventListener('click', () => {
    endSession();
    showPage('page-landing');
  });

  /* ── Intrusion close ── */
  document.getElementById('intrusion-close-btn').addEventListener('click', () => {
    document.getElementById('intrusion-overlay').classList.remove('show');
  });

  /* ── User dashboard: show encryption of username ── */
  document.getElementById('btn-show-encryption').addEventListener('click', () => {
    const enc = xorEncrypt(session.username);
    document.getElementById('ud-enc-show').textContent = enc;
  });

  /* ── Change password modal ── */
  document.getElementById('btn-change-password').addEventListener('click', () => openModal('modal-change-password'));
  document.getElementById('form-change-password').addEventListener('submit', handleChangePassword);
  document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
  });

  /* ── Admin: reset form ── */
  document.getElementById('form-reset-password').addEventListener('submit', handleAdminReset);

  /* ── Admin: refresh table button ── */
  document.getElementById('btn-refresh-users')?.addEventListener('click', () => {
    renderAdminDashboard();
    showAlert('admin-alert', 'info', 'Data refreshed.');
  });

  /* ── Admin: clear logs ── */
  document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
    if (confirm('Clear all security logs?')) {
      localStorage.removeItem(LOG_KEY);
      logEvent('SYSTEM', session.username, 'Security log cleared by admin');
      renderLogViewer();
    }
  });

  /* ── Admin: encryption demo in dashboard ── */
  document.getElementById('admin-enc-input')?.addEventListener('input', e => {
    updateEncryptionDemo(e.target.value, 'admin-enc-output');
    document.getElementById('admin-dec-output').textContent =
      e.target.value.length > 0 ? xorDecrypt(xorEncrypt(e.target.value)) : '—';
  });
});
