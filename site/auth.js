/**
 * ─────────────────────────────────────────────────────────────
 * Dragon CV — OIDC Authentication Module
 * ─────────────────────────────────────────────────────────────
 * 
 * Module này xử lý toàn bộ SSO login flow cho CV website:
 * 
 *  1. User mở CV website
 *  2. auth.js kiểm tra có access_token không
 *  3. Nếu CHƯA CÓ → hiển thị login screen, ấn nút → redirect sang SSO
 *  4. SSO hiển thị login form → user nhập username/password
 *  5. Login thành công → SSO redirect về /callback.html kèm authorization code
 *  6. callback.html exchange code → access_token (PKCE flow)
 *  7. Lưu token → redirect về trang chính → hiển thị CV
 * 
 * Sử dụng oidc-client-ts library (CDN) cho OIDC Authorization Code + PKCE.
 * PKCE (Proof Key for Code Exchange) bảo vệ chống code interception attack.
 * 
 * Cấu hình:
 *   - authority: URL của SSO server (Identity Service qua API Gateway)
 *   - client_id: "CV_Website" (đã seed trong IdentityServiceDataSeeder)
 *   - redirect_uri: /callback.html
 * ─────────────────────────────────────────────────────────────
 */

// ── Cấu hình OIDC ──────────────────────────────────────────
// Đọc từ window.__AUTH_CONFIG nếu có (inject từ server),
// fallback về Cloudflare Tunnel URL
const AUTH_CONFIG = window.__AUTH_CONFIG || {
    // URL SSO server — thay bằng Cloudflare Tunnel URL thực tế
    authority: 'https://dragon-sso.trycloudflare.com',
    // Client ID đã đăng ký trong IdentityServiceDataSeeder
    clientId: 'CV_Website',
    // Callback page xử lý authorization code
    redirectUri: window.location.origin + '/callback.html',
    // Redirect về đây sau khi logout
    postLogoutRedirectUri: window.location.origin + '/',
    // Scopes yêu cầu: openid (bắt buộc) + profile + email + roles
    scope: 'openid profile email roles IdentityService',
};

// ── State management ────────────────────────────────────────
const TOKEN_KEY = 'dragon_cv_auth';

/**
 * Lấy stored auth data từ sessionStorage.
 * Dùng sessionStorage thay localStorage vì:
 * - Token tự hết khi đóng tab (an toàn hơn)
 * - Phù hợp cho demo/learning
 */
function getAuthData() {
    try {
        const data = sessionStorage.getItem(TOKEN_KEY);
        if (!data) return null;
        const parsed = JSON.parse(data);
        // Kiểm tra token hết hạn chưa
        if (parsed.expiresAt && Date.now() > parsed.expiresAt * 1000) {
            sessionStorage.removeItem(TOKEN_KEY);
            return null;
        }
        return parsed;
    } catch {
        sessionStorage.removeItem(TOKEN_KEY);
        return null;
    }
}

function setAuthData(data) {
    sessionStorage.setItem(TOKEN_KEY, JSON.stringify(data));
}

function clearAuthData() {
    sessionStorage.removeItem(TOKEN_KEY);
}

// ── PKCE Helper Functions ───────────────────────────────────
// PKCE tạo code_verifier (random) và code_challenge (SHA256 hash)
// Để SSO server verify: client gửi code nào thì phải match challenge đã gửi lúc authorize

/**
 * Tạo random string cho code_verifier
 * Spec yêu cầu 43-128 characters, URL-safe
 */
function generateCodeVerifier() {
    const array = new Uint8Array(64);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

/**
 * SHA256 hash code_verifier → code_challenge
 * Server so sánh hash(code_verifier gửi lúc token) === code_challenge gửi lúc authorize
 */
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(buffer) {
    let str = '';
    for (const byte of buffer) {
        str += String.fromCharCode(byte);
    }
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Generate random state parameter
 * Chống CSRF: state gửi đi phải match state nhận về
 */
function generateState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

// ── Login Flow ──────────────────────────────────────────────

/**
 * Bắt đầu OIDC Authorization Code + PKCE flow
 * 
 * Step 1: Tạo code_verifier + code_challenge + state
 * Step 2: Lưu vào sessionStorage (cần dùng lại ở callback)
 * Step 3: Redirect browser sang SSO /connect/authorize
 */
async function login() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateState();

    // Lưu PKCE data để callback.html dùng
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    sessionStorage.setItem('pkce_state', state);

    // Build authorization URL
    const params = new URLSearchParams({
        client_id: AUTH_CONFIG.clientId,
        redirect_uri: AUTH_CONFIG.redirectUri,
        response_type: 'code',
        scope: AUTH_CONFIG.scope,
        state: state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
    });

    // Redirect sang SSO login page
    window.location.href = `${AUTH_CONFIG.authority}/connect/authorize?${params}`;
}

/**
 * Xử lý callback từ SSO (gọi từ callback.html)
 * 
 * Step 4: Parse authorization code từ URL
 * Step 5: Verify state (chống CSRF)
 * Step 6: Exchange code + code_verifier → access_token
 * Step 7: Lưu token và redirect về main page
 */
async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');

    // Kiểm tra lỗi từ SSO
    if (error) {
        console.error('SSO Error:', error, params.get('error_description'));
        window.location.href = '/?error=' + encodeURIComponent(error);
        return;
    }

    if (!code) {
        window.location.href = '/?error=no_code';
        return;
    }

    // Verify state (chống CSRF attack)
    const savedState = sessionStorage.getItem('pkce_state');
    if (state !== savedState) {
        console.error('State mismatch! Possible CSRF attack.');
        window.location.href = '/?error=state_mismatch';
        return;
    }

    // Lấy code_verifier đã lưu
    const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
    if (!codeVerifier) {
        window.location.href = '/?error=no_verifier';
        return;
    }

    try {
        // Exchange authorization code → token
        const tokenResponse = await fetch(`${AUTH_CONFIG.authority}/connect/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: AUTH_CONFIG.clientId,
                code: code,
                redirect_uri: AUTH_CONFIG.redirectUri,
                code_verifier: codeVerifier,
            }),
        });

        if (!tokenResponse.ok) {
            const err = await tokenResponse.text();
            console.error('Token exchange failed:', err);
            window.location.href = '/?error=token_exchange';
            return;
        }

        const tokenData = await tokenResponse.json();

        // Decode JWT để lấy user info (không cần verify vì chỉ hiển thị)
        const userInfo = parseJwt(tokenData.access_token || tokenData.id_token);

        // Lưu auth data
        setAuthData({
            accessToken: tokenData.access_token,
            idToken: tokenData.id_token,
            refreshToken: tokenData.refresh_token,
            expiresAt: Math.floor(Date.now() / 1000) + (tokenData.expires_in || 3600),
            user: {
                name: userInfo.name || userInfo.preferred_username || userInfo.sub,
                email: userInfo.email || '',
                role: userInfo.role || userInfo.roles || '',
            },
        });

        // Cleanup PKCE data
        sessionStorage.removeItem('pkce_code_verifier');
        sessionStorage.removeItem('pkce_state');

        // Redirect về main page
        window.location.href = '/';
    } catch (err) {
        console.error('Callback error:', err);
        window.location.href = '/?error=callback_failed';
    }
}

/**
 * Decode JWT payload (không verify signature — chỉ để hiển thị user info)
 */
function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );
        return JSON.parse(jsonPayload);
    } catch {
        return {};
    }
}

// ── Logout Flow ─────────────────────────────────────────────

/**
 * Logout: xóa token local + redirect sang SSO logout endpoint
 * SSO sẽ invalidate session và redirect về post_logout_redirect_uri
 */
function logout() {
    const authData = getAuthData();
    clearAuthData();

    if (authData?.idToken) {
        // Redirect sang SSO logout để invalidate server-side session
        const params = new URLSearchParams({
            id_token_hint: authData.idToken,
            post_logout_redirect_uri: AUTH_CONFIG.postLogoutRedirectUri,
        });
        window.location.href = `${AUTH_CONFIG.authority}/connect/logout?${params}`;
    } else {
        window.location.href = '/';
    }
}

// ── UI Helpers ──────────────────────────────────────────────

/**
 * Kiểm tra user đã login chưa và toggle UI tương ứng
 * Gọi từ index.html khi page load
 */
function initAuth() {
    const authData = getAuthData();
    const loginGate = document.getElementById('login-gate');
    const cvContent = document.getElementById('cv-content');
    const userBar = document.getElementById('user-bar');
    const userName = document.getElementById('user-name');
    const userEmail = document.getElementById('user-email');

    if (authData) {
        // ✅ Đã login → hiển thị CV
        if (loginGate) loginGate.style.display = 'none';
        if (cvContent) cvContent.style.display = 'block';
        if (userBar) userBar.style.display = 'flex';
        if (userName) userName.textContent = authData.user?.name || 'User';
        if (userEmail) userEmail.textContent = authData.user?.email || '';
    } else {
        // ❌ Chưa login → hiển thị login gate
        if (loginGate) loginGate.style.display = 'flex';
        if (cvContent) cvContent.style.display = 'none';
        if (userBar) userBar.style.display = 'none';
    }

    // Kiểm tra error từ callback
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    if (error) {
        const errorEl = document.getElementById('login-error');
        if (errorEl) {
            errorEl.textContent = `Authentication error: ${error}`;
            errorEl.style.display = 'block';
        }
        // Xóa error từ URL
        window.history.replaceState({}, '', '/');
    }
}

// Auto-init khi DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAuth);
} else {
    initAuth();
}
