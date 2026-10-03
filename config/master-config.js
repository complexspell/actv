// 主配置文件 - 所有密码和核心配置的唯一来源
// 只需要在这里修改，其他文件会自动同步

const MASTER_CONFIG = {
    // 🔐 核心认证配置（只需要在这里修改）
    auth: {
        username: 'admin',                    // 用户名
        password: '222',            // 【改动1】原来是 'admin123'，改成你的密码
        enabled: true,                        // 是否启用密码保护
        sessionDuration: 90 * 24 * 60 * 60 * 1000,  // 90天
        maxLoginAttempts: 5,                  // 最大尝试次数
        lockoutDuration: 30 * 60 * 1000       // 锁定时间30分钟
    },

    // 🌐 代理服务配置
    proxy: {
        debug: false,
        cacheEnabled: true,
        cacheTTL: 86400,
        maxRecursion: 5,
        timeout: 10000,
        userAgents: [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
    },

    // 📱 UI配置
    ui: {
        title: 'LibreTV',
        loginTitle: 'LibreTV 访问验证',
        loginPrompt: '请输入访问密码',
        theme: 'dark'
    },

    // ⚙️ 应用配置
    app: {
        version: '2.0.0',
        environment: 'production'
    }
};

// ============================================================
// 【改动2】新增：纯 JS SHA-256 实现
// 目的：在 HTTP + IP 访问时（非安全上下文），浏览器不提供 crypto.subtle，
//       用一个不依赖浏览器安全上下文的纯 JS 实现代替。
// 位置：插在 generatePasswordHash 函数之前
// ============================================================
function sha256Pure(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    let result = '';
    const words = [];
    const asciiBitLength = ascii.length * 8;
    let hash = sha256Pure.h = sha256Pure.h || [];
    const k = sha256Pure.k = sha256Pure.k || [];
    let primeCounter = k.length;
    const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (let i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (let i = 0; i < ascii.length; i++) {
        const j = ascii.charCodeAt(i);
        if (j >> 8) return;
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength);
    for (let j = 0; j < words.length;) {
        const w = words.slice(j, j += 16);
        const oldHash = hash;
        hash = hash.slice(0, 8);
        for (let i = 0; i < 64; i++) {
            const w15 = w[i - 15], w2 = w[i - 2];
            const a = hash[0], e = hash[4];
            const temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                + ((e & hash[5]) ^ ((~e) & hash[6]))
                + k[i]
                + (w[i] = (i < 16) ? w[i] : (
                    w[i - 16]
                    + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
                    + w[i - 7]
                    + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                ) | 0
                );
            const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
        }
        for (let i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }
    for (let i = 0; i < 8; i++) {
        for (let j = 3; j + 1; j--) {
            const b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
}

// ============================================================
// 【改动3】重写：generatePasswordHash
// 原来：只用 crypto.subtle 或 require('crypto')
// 现在：三级判断，HTTP + IP 时走 sha256Pure
// ============================================================
async function generatePasswordHash(password) {
    // 优先尝试 Web Crypto（HTTPS / localhost 环境）
    if (typeof crypto !== 'undefined' && crypto.subtle
        && typeof window !== 'undefined' && window.isSecureContext) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            console.warn('Web Crypto 失败，改用纯 JS SHA-256:', e);
        }
    }
    // Node.js 环境
    if (typeof require !== 'undefined' && typeof window === 'undefined') {
        const cryptoNode = require('crypto');
        return cryptoNode.createHash('sha256').update(password).digest('hex');
    }
    // 非安全上下文（HTTP + IP）→ 纯 JS
    return sha256Pure(password);
}

// 初始化配置（自动计算密码哈希）
async function initializeConfig() {
    if (!MASTER_CONFIG.auth.password) {
        console.error('❌ 主配置中未设置密码');
        return;
    }

    try {
        console.log('🔐 开始计算密码哈希，密码:', MASTER_CONFIG.auth.password);
        MASTER_CONFIG.auth.passwordHash = await generatePasswordHash(MASTER_CONFIG.auth.password);
        console.log('✅ 密码哈希计算完成:', MASTER_CONFIG.auth.passwordHash);

        if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('masterConfigReady', {
                detail: { config: MASTER_CONFIG }
            }));
        }
    } catch (error) {
        console.error('❌ 密码哈希计算失败:', error);
        console.error('详细错误:', error.stack);

        try {
            if (typeof window !== 'undefined' && window.crypto && crypto.subtle) {
                const encoder = new TextEncoder();
                const data = encoder.encode(MASTER_CONFIG.auth.password);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                MASTER_CONFIG.auth.passwordHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                console.log('✅ 使用Web Crypto API计算密码哈希成功:', MASTER_CONFIG.auth.passwordHash);
            } else {
                throw new Error('无可用的哈希计算方法');
            }
        } catch (fallbackError) {
            console.error('❌ 后备哈希计算也失败:', fallbackError);
            MASTER_CONFIG.auth.passwordHash = null;
        }
    }
}

// 获取配置的便捷函数
function getAuthConfig() {
    return MASTER_CONFIG.auth;
}

function getProxyConfig() {
    return MASTER_CONFIG.proxy;
}

function getUIConfig() {
    return MASTER_CONFIG.ui;
}

function getAppConfig() {
    return MASTER_CONFIG.app;
}

function getPassword() {
    return MASTER_CONFIG.auth.password;
}

async function getPasswordHash() {
    if (!MASTER_CONFIG.auth.passwordHash) {
        await initializeConfig();
    }
    return MASTER_CONFIG.auth.passwordHash;
}

// 立即初始化
if (typeof window !== 'undefined') {
    console.log('🔧 开始初始化主配置...');

    window.MASTER_CONFIG_READY = false;

    initializeConfig().then(() => {
        console.log('🎉 主配置初始化完成');
        window.MASTER_CONFIG_READY = true;

        window.dispatchEvent(new CustomEvent('masterConfigReady', {
            detail: { config: MASTER_CONFIG }
        }));
    }).catch(error => {
        console.error('❌ 主配置初始化失败:', error);

        try {
            if (MASTER_CONFIG.auth.password) {
                console.log('🔄 尝试后备密码哈希计算...');
                const encoder = new TextEncoder();
                const data = encoder.encode(MASTER_CONFIG.auth.password);
                crypto.subtle.digest('SHA-256', data).then(hashBuffer => {
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    MASTER_CONFIG.auth.passwordHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    console.log('✅ 后备密码哈希计算完成:', MASTER_CONFIG.auth.passwordHash);
                    window.MASTER_CONFIG_READY = true;

                    window.dispatchEvent(new CustomEvent('masterConfigReady', {
                        detail: { config: MASTER_CONFIG }
                    }));
                }).catch(fallbackError => {
                    console.error('❌ 后备哈希计算也失败:', fallbackError);
                    window.MASTER_CONFIG_READY = true;
                });
            } else {
                console.error('❌ 主配置中没有密码，无法计算哈希');
                window.MASTER_CONFIG_READY = true;
            }
        } catch (fallbackError) {
            console.error('❌ 后备哈希计算准备失败:', fallbackError);
            window.MASTER_CONFIG_READY = true;
        }
    });
} else if (typeof global !== 'undefined') {
    initializeConfig();
}

// 导出配置（兼容浏览器和Node.js）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        MASTER_CONFIG,
        getAuthConfig,
        getProxyConfig,
        getUIConfig,
        getAppConfig,
        getPassword,
        getPasswordHash,
        generatePasswordHash
    };
} else {
    window.MASTER_CONFIG = MASTER_CONFIG;
    window.getAuthConfig = getAuthConfig;
    window.getProxyConfig = getProxyConfig;
    window.getUIConfig = getUIConfig;
    window.getAppConfig = getAppConfig;
    window.getPassword = getPassword;
    window.getPasswordHash = getPasswordHash;
    window.generatePasswordHash = generatePasswordHash;

    window.updateMasterPassword = async function(newPassword) {
        if (MASTER_CONFIG && MASTER_CONFIG.auth) {
            const oldPassword = MASTER_CONFIG.auth.password;
            MASTER_CONFIG.auth.password = newPassword;

            try {
                const newHash = await generatePasswordHash(newPassword);
                MASTER_CONFIG.auth.passwordHash = newHash;
                console.log('✅ 密码和哈希已更新');

                window.dispatchEvent(new CustomEvent('passwordUpdated', {
                    detail: {
                        oldPassword: oldPassword,
                        newPassword: newPassword,
                        newHash: newHash
                    }
                }));

                return { success: true, newHash: newHash };
            } catch (error) {
                console.error('❌ 哈希计算失败:', error);
                return { success: false, error: error.message };
            }
        }
        return { success: false, error: '配置对象不存在' };
    };

    window.getCurrentPasswordInfo = function() {
        if (MASTER_CONFIG && MASTER_CONFIG.auth) {
            return {
                password: MASTER_CONFIG.auth.password,
                hash: MASTER_CONFIG.auth.passwordHash,
                username: MASTER_CONFIG.auth.username
            };
        }
        return null;
    };
}

if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
    console.log('🔧 LibreTV 主配置已加载');
    console.log('👤 用户名:', MASTER_CONFIG.auth.username);
    console.log('🔒 密码保护:', MASTER_CONFIG.auth.enabled ? '已启用' : '已禁用');
    console.log('🌐 代理调试:', MASTER_CONFIG.proxy.debug ? '已启用' : '已禁用');
}
