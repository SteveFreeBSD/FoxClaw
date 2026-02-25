import Database from "better-sqlite3";
import crypto from "crypto";
import fs from "fs";
import path from "path";

// ── Globals & Fast Mode ──────────────────────────────────────────────
let FAST_MODE = false;
let JSONL_STREAM = null;
let JSONL_PROFILE = "";
let JSONL_SCENARIO = "";

function emitJsonl(entry) {
    if (!JSONL_STREAM) return;
    JSONL_STREAM.write(
        JSON.stringify({ ts: new Date().toISOString(), profile: JSONL_PROFILE, scenario: JSONL_SCENARIO, ...entry }) + "\n"
    );
}

// Browsing URL pool — used for SQLite history generation
const HISTORY_URL_POOL = [
    { url: "https://www.google.com/search?q=firefox+security+settings", title: "firefox security settings - Google Search" },
    { url: "https://duckduckgo.com/?q=how+to+export+passwords", title: "how to export passwords at DuckDuckGo" },
    { url: "https://en.wikipedia.org/wiki/Browser_security", title: "Browser security - Wikipedia" },
    { url: "https://news.ycombinator.com/", title: "Hacker News" },
    { url: "https://www.mozilla.org/en-US/firefox/", title: "Firefox Browser" },
    { url: "https://developer.mozilla.org/en-US/docs/Web/Security", title: "Web security | MDN" },
    { url: "https://www.bbc.com/news", title: "BBC News" },
    { url: "https://www.npr.org/", title: "NPR" },
    { url: "https://arstechnica.com/", title: "Ars Technica" },
    { url: "https://github.com/explore", title: "Explore GitHub" },
    { url: "https://stackoverflow.com/questions", title: "Questions - Stack Overflow" },
    { url: "https://www.reddit.com/r/firefox", title: "r/firefox" },
    { url: "https://www.amazon.com/", title: "Amazon.com" },
    { url: "https://mail.google.com/", title: "Gmail" },
    { url: "https://accounts.google.com/signin", title: "Sign in - Google Accounts" },
    { url: "https://login.microsoftonline.com/", title: "Sign in to your account" },
    { url: "https://www.paypal.com/signin", title: "Log in to your PayPal account" },
    { url: "https://online.bankofamerica.com/", title: "Bank of America Online Banking" },
    { url: "http://legacy-intranet.example.test/dashboard", title: "Intranet Dashboard" },
    { url: "http://192.168.1.1/admin", title: "Router Admin" },
    { url: "https://www.cnet.com/tech/", title: "Tech News - CNET" },
    { url: "https://www.techradar.com/", title: "TechRadar" },
    { url: "https://archive.org/", title: "Internet Archive" },
    { url: "https://lobste.rs/", title: "Lobsters" },
    { url: "https://www.nasa.gov/", title: "NASA" },
];
function computeConfigHash() {
    const configData = JSON.stringify({
        // Minimal set to detect major drift; can extend later
        // allowedDomains: [...ALLOWED_DOMAINS].sort() // Removed as ALLOWED_DOMAINS is no longer used
    });
    return crypto.createHash("sha256").update(configData).digest("hex").slice(0, 16);
}

function sleep(ms) {
    const duration = FAST_MODE ? Math.min(100, Math.floor(ms / 10)) : ms;
    return new Promise((resolve) => setTimeout(resolve, duration));
}

function hashToSeedInt(seedInput) {
    const digest = crypto.createHash("sha256").update(String(seedInput)).digest();
    const value = digest.readUInt32LE(0);
    return value === 0 ? 0x9e3779b9 : value;
}

function makeRng(seedInput) {
    let state = hashToSeedInt(seedInput) >>> 0;
    return () => {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        state >>>= 0;
        return state / 0x100000000;
    };
}

function randInt(rng, minInclusive, maxInclusive) {
    const span = maxInclusive - minInclusive + 1;
    return minInclusive + Math.floor(rng() * span);
}

function chance(rng, probability) {
    return rng() < probability;
}

function pickSome(arr, n, rng) {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy.slice(0, n);
}

function safeMkdir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function appendAction(actionLog, payload) {
    const entry = {
        at_utc: new Date().toISOString(),
        ...payload,
    };
    actionLog.push(entry);
    emitJsonl(entry);
}

function summarizeStages(actionLog) {
    const counts = {};
    for (const item of actionLog) {
        const key = typeof item.stage === "string" ? item.stage : "unknown";
        counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
}

const SEARCH_TERMS = [
    "best firefox privacy extensions",
    "invoice template xlsm",
    "browser update security advisory",
    "how to export passwords firefox",
    "remote support browser plugin",
    "sso login issue troubleshooting",
];

const DOWNLOAD_NAMES = [
    "invoice-2026-02.pdf",
    "payroll-adjustment.xlsm",
    "browser-update-patch.zip",
    "vpn-client-installer.msi",
    "customer-export.csv",
];

// ── Weak / common password pool (scanner should flag these) ──────────
const WEAK_PASSWORDS = [
    "Password1",
    "123456",
    "password",
    "admin",
    "letmein",
    "welcome1",
    "company2024",
    "qwerty123",
    "changeme",
    "abc123",
    "iloveyou",
    "trustno1",
    "dragon",
    "master",
    "monkey123",
];

// Encrypted-blob markers — these are NOT real encrypted data.
// Each maps to a recognizable plaintext-equivalent marker so scanners
// can pattern-match weak credentials without needing the master key.
function weakPasswordBlob(plaintext) {
    const tag = crypto.createHash("md5").update(plaintext).digest("hex").slice(0, 8);
    return `MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECweak-${tag}`;
}

// ── Suspicious extension definitions ─────────────────────────────────
const SUSPICIOUS_EXTENSION_TEMPLATES = [
    {
        namePrefix: "PDF Converter Pro",
        permissions: ["<all_urls>", "webRequest", "webRequestBlocking", "tabs", "storage", "cookies"],
        content_scripts: [{ matches: ["<all_urls>"], js: ["inject.js"] }],
        sideloaded: false,
        unsigned: true,
    },
    {
        namePrefix: "Browser Speed Booster",
        permissions: ["<all_urls>", "webRequest", "webRequestBlocking", "proxy", "management"],
        content_scripts: [{ matches: ["*://*/*"], js: ["perf.js"], run_at: "document_start" }],
        sideloaded: true,
        unsigned: true,
    },
    {
        namePrefix: "Free VPN Unlimited",
        permissions: ["<all_urls>", "proxy", "webRequest", "webRequestBlocking", "dns"],
        content_scripts: [],
        sideloaded: false,
        unsigned: true,
    },
    {
        namePrefix: "AdBlock Super",
        permissions: ["<all_urls>", "webRequest", "webRequestBlocking", "tabs", "webNavigation"],
        content_scripts: [{ matches: ["<all_urls>"], js: ["block.js"], all_frames: true }],
        sideloaded: true,
        unsigned: false,
    },
    {
        namePrefix: "Shopping Helper",
        permissions: ["<all_urls>", "tabs", "cookies", "storage", "history"],
        content_scripts: [{ matches: ["*://*.amazon.com/*", "*://*.ebay.com/*", "*://*/*"], js: ["deals.js"] }],
        sideloaded: false,
        unsigned: false,
    },
    {
        namePrefix: "Screenshot Capture Tool",
        permissions: ["<all_urls>", "activeTab", "clipboardWrite", "downloads", "tabs", "nativeMessaging"],
        content_scripts: [{ matches: ["<all_urls>"], js: ["capture.js"] }],
        sideloaded: true,
        unsigned: true,
    },
    {
        namePrefix: "Crypto Wallet Manager",
        permissions: ["<all_urls>", "webRequest", "storage", "cookies", "clipboardRead", "clipboardWrite"],
        content_scripts: [{ matches: ["*://*/*"], js: ["wallet.js"], run_at: "document_start" }],
        sideloaded: false,
        unsigned: true,
    },
];

// ── Expanded dangerous user.js preferences ───────────────────────────
const DANGEROUS_PREFS = {
    // Core privacy / safe-browsing
    core: [
        ['privacy.clearOnShutdown.cookies', false],
        ['signon.autofillForms', true],
        ['network.cookie.lifetimePolicy', 0],
        ['extensions.autoDisableScopes', 0],
    ],
    // Safe-browsing disabled
    safebrowsing: [
        ['browser.safebrowsing.malware.enabled', false],
        ['browser.safebrowsing.phishing.enabled', false],
        ['browser.safebrowsing.downloads.enabled', false],
        ['browser.safebrowsing.downloads.remote.enabled', false],
    ],
    // TLS / transport weakening
    tls: [
        ['security.tls.version.min', 1],
        ['security.ssl.require_safe_negotiation', false],
        ['network.stricttransportsecurity.preloadlist', false],
        ['security.OCSP.enabled', 0],
    ],
    // Content security
    content: [
        ['security.csp.enable', false],
        ['security.mixed_content.block_active_content', false],
        ['security.mixed_content.block_display_content', false],
        ['dom.security.https_only_mode', false],
        ['dom.security.https_only_mode.ever_enabled', false],
    ],
    // Proxy / network
    proxy: [
        ['network.proxy.type', 1],
        ['network.proxy.http', '10.255.0.1'],
        ['network.proxy.http_port', 8080],
        ['network.proxy.ssl', '10.255.0.1'],
        ['network.proxy.ssl_port', 8080],
        ['network.proxy.no_proxies_on', ''],
    ],
};

// Which pref groups each scenario enables
const SCENARIO_PREF_GROUPS = {
    balanced: ['core'],
    credential_reuse: ['core', 'safebrowsing'],
    privacy_weak: ['core', 'safebrowsing', 'tls', 'content'],
    adware_like: ['core', 'safebrowsing', 'content', 'proxy'],
    dev_power_user: ['core'],
};

// ── SQL injection / XSS payload pool ─────────────────────────────────
const SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "1; DROP TABLE users --",
    "' UNION SELECT username, password FROM users --",
    "admin'--",
    "1' OR '1'='1",
    "'; EXEC xp_cmdshell('dir'); --",
    "' UNION ALL SELECT NULL, NULL, CONCAT(username,':',password) FROM users --",
    "1 AND 1=1 UNION SELECT 1,2,3,table_name FROM information_schema.tables --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a') --",
    "1'; WAITFOR DELAY '00:00:05'; --",
];

const XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(document.cookie)>',
    '" onfocus=alert(1) autofocus="',
    "javascript:alert('XSS')",
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '${7*7}',
    '{{constructor.constructor("return this")().alert(1)}}',
];

// ── Insecure cookie templates ────────────────────────────────────────
const INSECURE_COOKIE_TEMPLATES = [
    { name: "session_id", value: "s:{MARKER}", domain: ".example.com", secure: false, httpOnly: false, sameSite: "None" },
    { name: "auth_token", value: "tok_{MARKER}", domain: ".example.com", secure: false, httpOnly: false, sameSite: "Lax" },
    { name: "user_prefs", value: "lang=en&theme=dark", domain: ".example.com", secure: false, httpOnly: false, sameSite: "None" },
    { name: "tracking_uid", value: "uid_{MARKER}", domain: ".example.com", secure: false, httpOnly: false, sameSite: "None" },
    { name: "admin_session", value: "adm_{MARKER}", domain: ".example.com", secure: false, httpOnly: false, sameSite: "None" },
    { name: "remember_me", value: "1", domain: ".example.com", secure: false, httpOnly: false, sameSite: "Lax" },
    { name: "__csrf", value: "csrf_{MARKER}", domain: "example.com", secure: true, httpOnly: false, sameSite: "None" },
    { name: "analytics_id", value: "ga_{MARKER}", domain: ".example.com", secure: false, httpOnly: false, sameSite: "None" },
];

// ── Certificate override templates ───────────────────────────────────
const CERT_OVERRIDE_HOSTS = [
    { host: "expired-cert.internal.example.test", port: 443, reason: "expired", flags: "U" },
    { host: "self-signed.dev.example.test", port: 443, reason: "self-signed", flags: "U" },
    { host: "wrong-host.staging.example.test", port: 443, reason: "hostname-mismatch", flags: "M" },
    { host: "legacy-api.corp.example.test", port: 8443, reason: "expired", flags: "U" },
    { host: "vpn-portal.example.test", port: 443, reason: "self-signed", flags: "U" },
    { host: "build-server.ci.example.test", port: 443, reason: "untrusted-issuer", flags: "U" },
    { host: "iot-dashboard.local", port: 443, reason: "self-signed", flags: "U" },
];

// ── Autofill PII templates ───────────────────────────────────────────
const AUTOFILL_PII_TEMPLATES = [
    { fieldName: "ssn", value: "078-05-1120", sensitive: true },
    { fieldName: "ssn", value: "219-09-9999", sensitive: true },
    { fieldName: "cc-number", value: "4111111111111111", sensitive: true },
    { fieldName: "cc-number", value: "5500000000000004", sensitive: true },
    { fieldName: "cc-exp", value: "12/2028", sensitive: true },
    { fieldName: "cc-csc", value: "123", sensitive: true },
    { fieldName: "tel", value: "555-867-5309", sensitive: false },
    { fieldName: "email", value: "jdoe@example.test", sensitive: false },
    { fieldName: "street-address", value: "123 Main St", sensitive: false },
    { fieldName: "given-name", value: "Jane", sensitive: false },
    { fieldName: "family-name", value: "Doe", sensitive: false },
    { fieldName: "organization", value: "Acme Corp", sensitive: false },
];

const BASE_URL_POOL = [
    "https://en.wikipedia.org/wiki/Special:Random",
    "https://news.ycombinator.com/",
    "https://www.mozilla.org/",
    "https://developer.mozilla.org/",
    "https://www.bbc.com/",
    "https://www.npr.org/",
    "https://www.nasa.gov/",
    "https://arstechnica.com/",
    "https://github.com/explore",
    "https://lobste.rs/",
    "https://archive.org/",
    "https://www.openstreetmap.org/",
];

const SCENARIOS = {
    balanced: {
        site_min: 4,
        site_max: 7,
        login_rate: 0.35,
        form_rate: 0.45,
        download_rate: 0.25,
        permissions_rate: 0.55,
        storage_rate: 0.70,
        risky_settings: false,
        sqli_rate: 0.10,
        cert_override_rate: 0.05,
        autofill_rate: 0.20,
        insecure_cookie_rate: 0.15,
        extra_urls: ["https://www.reuters.com/", "https://www.nytimes.com/"],
    },
    adware_like: {
        site_min: 6,
        site_max: 10,
        login_rate: 0.20,
        form_rate: 0.35,
        download_rate: 0.80,
        permissions_rate: 0.80,
        storage_rate: 0.90,
        risky_settings: true,
        sqli_rate: 0.25,
        cert_override_rate: 0.60,
        autofill_rate: 0.40,
        insecure_cookie_rate: 0.75,
        extra_urls: [
            "https://www.cnet.com/",
            "https://www.techradar.com/",
            "https://www.majorgeeks.com/",
        ],
    },
    credential_reuse: {
        site_min: 5,
        site_max: 8,
        login_rate: 0.90,
        form_rate: 0.80,
        download_rate: 0.15,
        permissions_rate: 0.40,
        storage_rate: 0.75,
        risky_settings: true,
        sqli_rate: 0.35,
        cert_override_rate: 0.20,
        autofill_rate: 0.65,
        insecure_cookie_rate: 0.80,
        extra_urls: [
            "https://news.ycombinator.com/login",
            "https://httpbin.org/forms/post",
            "https://github.com/login",
        ],
    },
    privacy_weak: {
        site_min: 4,
        site_max: 7,
        login_rate: 0.30,
        form_rate: 0.40,
        download_rate: 0.35,
        permissions_rate: 0.90,
        storage_rate: 0.80,
        risky_settings: true,
        sqli_rate: 0.15,
        cert_override_rate: 0.45,
        autofill_rate: 0.55,
        insecure_cookie_rate: 0.70,
        extra_urls: ["https://www.openstreetmap.org/", "https://duckduckgo.com/"],
    },
    dev_power_user: {
        site_min: 5,
        site_max: 9,
        login_rate: 0.50,
        form_rate: 0.35,
        download_rate: 0.30,
        permissions_rate: 0.45,
        storage_rate: 0.65,
        risky_settings: false,
        sqli_rate: 0.45,
        cert_override_rate: 0.30,
        autofill_rate: 0.15,
        insecure_cookie_rate: 0.20,
        extra_urls: [
            "https://stackoverflow.com/",
            "https://docs.python.org/3/",
            "https://nodejs.org/en/docs",
        ],
    },
};

const SCENARIO_PICK_LIST = [
    "balanced",
    "balanced",
    "adware_like",
    "credential_reuse",
    "privacy_weak",
    "dev_power_user",
];

function parseArgs(argv) {
    if (argv.length < 1) {
        throw new Error(
            "usage: node mutate_profile.mjs <profileDir> [--scenario name] [--seed n] " +
            "[--profile-name name] [--manifest-out path]"
        );
    }

    const profileDir = argv[0];
    let scenario = "mixed";
    let seed = Date.now().toString();
    let profileName = path.basename(profileDir);
    let manifestOut = "";

    let fast = false;
    let extensionsCache = "";
    let jsonlLog = "";
    let buildCache = false;

    for (let i = 1; i < argv.length; i++) {
        const arg = argv[i];
        const next = argv[i + 1];
        if (arg === "--scenario" && next) {
            scenario = next;
            i += 1;
            continue;
        }
        if (arg === "--seed" && next) {
            seed = next;
            i += 1;
            continue;
        }
        if (arg === "--profile-name" && next) {
            profileName = next;
            i += 1;
            continue;
        }
        if (arg === "--manifest-out" && next) {
            manifestOut = next;
            i += 1;
            continue;
        }
        if (arg === "--extensions-cache" && next) {
            extensionsCache = next;
            i += 1;
            continue;
        }
        if (arg === "--jsonl-log" && next) {
            jsonlLog = next;
            i += 1;
            continue;
        }
        if (arg === "--fast") {
            fast = true;
            continue;
        }
        if (arg === "--build-cache") {
            buildCache = true;
            continue;
        }
        throw new Error(`unknown argument: ${arg}`);
    }

    return { profileDir, scenario, seed, profileName, manifestOut, fast, extensionsCache, jsonlLog, buildCache };
}

function selectScenario(name, rng) {
    if (name === "mixed") {
        const picked = SCENARIO_PICK_LIST[randInt(rng, 0, SCENARIO_PICK_LIST.length - 1)];
        return { name: picked, config: SCENARIOS[picked] };
    }
    if (!Object.prototype.hasOwnProperty.call(SCENARIOS, name)) {
        throw new Error(`unknown scenario: ${name}`);
    }
    return { name, config: SCENARIOS[name] };
}

// ══════════════════════════════════════════════════════════════════════════
// SQLite database writers — write directly to Firefox's real databases
// ══════════════════════════════════════════════════════════════════════════

function seedBrowsingHistory(profileDir, scenarioName, rng, actionLog) {
    const dbPath = path.join(profileDir, "places.sqlite");
    if (!fs.existsSync(dbPath)) {
        appendAction(actionLog, { stage: "browsing_history", status: "skipped", message: "places.sqlite not found" });
        return { history_entries_added: 0 };
    }

    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");

    const maxPlaceId = db.prepare("SELECT COALESCE(MAX(id), 0) as m FROM moz_places").get().m;
    const maxVisitId = db.prepare("SELECT COALESCE(MAX(id), 0) as m FROM moz_historyvisits").get().m;

    const scenarioConfig = SCENARIOS[scenarioName] || SCENARIOS.balanced;
    const allUrls = [...HISTORY_URL_POOL];
    if (scenarioConfig.extra_urls) {
        for (const u of scenarioConfig.extra_urls) {
            allUrls.push({ url: u, title: u.replace(/https?:\/\//, "").split("/")[0] });
        }
    }
    const entryCount = randInt(rng, 8, 25);
    const picked = pickSome(allUrls, Math.min(entryCount, allUrls.length), rng);

    const insertPlace = db.prepare(`
        INSERT OR IGNORE INTO moz_places (id, url, title, rev_host, visit_count, hidden, typed, frecency, last_visit_date)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
    `);
    const insertVisit = db.prepare(`
        INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session)
        VALUES (?, 0, ?, ?, ?, 0)
    `);

    let addedCount = 0;
    const insertAll = db.transaction(() => {
        for (let i = 0; i < picked.length; i++) {
            const entry = picked[i];
            const placeId = maxPlaceId + i + 1;
            const visitId = maxVisitId + i + 1;
            const visitCount = randInt(rng, 1, 30);
            const typed = entry.url.includes("login") || entry.url.includes("signin") ? 1 : 0;
            const frecency = randInt(rng, 100, 10000);
            // Backdate: spread visits across 7-90 days ago (microseconds)
            const daysAgo = randInt(rng, 7, 90);
            const lastVisit = (Date.now() - daysAgo * 86400000) * 1000;
            let revHost = ".";
            try {
                const hostname = new URL(entry.url).hostname;
                revHost = hostname.split("").reverse().join("") + ".";
            } catch { /* keep default */ }

            insertPlace.run(placeId, entry.url, entry.title, revHost, visitCount, typed, frecency, lastVisit);

            // Multiple visits spread over the past N days for realism
            const numVisits = randInt(rng, 1, 8);
            for (let v = 0; v < numVisits; v++) {
                // Each visit on a different day within the range
                const visitDaysAgo = randInt(rng, daysAgo, daysAgo + 30);
                const visitDate = (Date.now() - visitDaysAgo * 86400000 + randInt(rng, 0, 86400000)) * 1000;
                // Visit types: 1=link, 2=typed, 3=bookmark, 5=embed, 6=redirect_permanent
                const visitTypes = [1, 1, 1, 2, 3, 5, 6];
                const visitType = visitTypes[randInt(rng, 0, visitTypes.length - 1)];
                insertVisit.run(visitId + v * 100, placeId, visitDate, visitType);
            }
            addedCount++;
        }
    });
    insertAll();
    db.close();

    const signal = { history_entries_added: addedCount };
    appendAction(actionLog, { stage: "browsing_history", status: "ok", ...signal });
    return signal;
}

function seedCookiesDatabase(profileDir, scenarioName, rng, actionLog) {
    const dbPath = path.join(profileDir, "cookies.sqlite");
    if (!fs.existsSync(dbPath)) {
        appendAction(actionLog, { stage: "cookies_db", status: "skipped", message: "cookies.sqlite not found" });
        return { cookies_db_entries: 0, missing_secure: 0, missing_httponly: 0 };
    }

    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");

    const count = scenarioName === "credential_reuse" || scenarioName === "adware_like"
        ? randInt(rng, 5, 10)
        : randInt(rng, 2, 6);
    const picked = pickSome(INSECURE_COOKIE_TEMPLATES, Math.min(count, INSECURE_COOKIE_TEMPLATES.length), rng);
    const marker = `${Date.now()}-${randInt(rng, 1000, 9999)}`;

    const insert = db.prepare(`
        INSERT OR REPLACE INTO moz_cookies (originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite, schemeMap)
        VALUES ('', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0)
    `);

    let missingSecure = 0;
    let missingHttpOnly = 0;

    const insertAll = db.transaction(() => {
        for (let i = 0; i < picked.length; i++) {
            const tmpl = picked[i];
            const now = Date.now() * 1000;
            const expiry = Math.floor(Date.now() / 1000) + randInt(rng, 86400, 315360000);
            const sameSiteVal = tmpl.sameSite === "None" ? 0 : tmpl.sameSite === "Lax" ? 1 : 2;

            insert.run(
                tmpl.name + `_${i}`,
                tmpl.value.replace("{MARKER}", `${marker}-${i}`),
                tmpl.domain,
                "/",
                expiry,
                now,
                now - randInt(rng, 1000000, 86400000000),
                tmpl.secure ? 1 : 0,
                tmpl.httpOnly ? 1 : 0,
                sameSiteVal
            );

            if (!tmpl.secure) missingSecure++;
            if (!tmpl.httpOnly) missingHttpOnly++;
        }
    });
    insertAll();
    db.close();

    const signal = {
        cookies_db_entries: picked.length,
        missing_secure: missingSecure,
        missing_httponly: missingHttpOnly,
    };
    appendAction(actionLog, { stage: "cookies_db", status: "ok", ...signal });
    return signal;
}

function seedFormHistoryDatabase(profileDir, scenarioName, rng, actionLog) {
    const dbPath = path.join(profileDir, "formhistory.sqlite");

    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");

    db.exec(`
        CREATE TABLE IF NOT EXISTS moz_formhistory (
            id INTEGER PRIMARY KEY,
            fieldname TEXT NOT NULL,
            value TEXT NOT NULL,
            timesUsed INTEGER,
            firstUsed INTEGER,
            lastUsed INTEGER
        )
    `);

    const sqliCount = randInt(rng, 2, 5);
    const xssCount = randInt(rng, 1, 4);
    const sqliPicked = pickSome(SQLI_PAYLOADS, Math.min(sqliCount, SQLI_PAYLOADS.length), rng);
    const xssPicked = pickSome(XSS_PAYLOADS, Math.min(xssCount, XSS_PAYLOADS.length), rng);

    const fieldNames = ["search", "q", "username", "email", "comment", "input", "query", "filter"];
    const insert = db.prepare(`
        INSERT INTO moz_formhistory (fieldname, value, timesUsed, firstUsed, lastUsed)
        VALUES (?, ?, ?, ?, ?)
    `);

    const insertAll = db.transaction(() => {
        for (const payload of sqliPicked) {
            const now = Date.now() * 1000;
            insert.run(
                fieldNames[randInt(rng, 0, fieldNames.length - 1)],
                payload,
                randInt(rng, 1, 8),
                now - randInt(rng, 86400000000, 31536000000000),
                now - randInt(rng, 3600000000, 86400000000)
            );
        }
        for (const payload of xssPicked) {
            const now = Date.now() * 1000;
            insert.run(
                fieldNames[randInt(rng, 0, fieldNames.length - 1)],
                payload,
                randInt(rng, 1, 5),
                now - randInt(rng, 86400000000, 31536000000000),
                now - randInt(rng, 3600000000, 86400000000)
            );
        }
    });
    insertAll();
    db.close();

    const signal = {
        sqli_payload_count: sqliPicked.length,
        xss_payload_count: xssPicked.length,
        total_formhistory_entries: sqliPicked.length + xssPicked.length,
    };
    appendAction(actionLog, { stage: "formhistory_db", status: "ok", ...signal });
    return signal;
}

function writeScenarioArtifacts(profileDir, scenarioName, seed, riskySettings, actionLog) {
    const artifactDir = path.join(profileDir, "foxclaw-sim");
    safeMkdir(artifactDir);

    const timelinePath = path.join(artifactDir, "timeline.log");
    const markerPath = path.join(artifactDir, "scenario-marker.json");
    fs.writeFileSync(timelinePath, actionLog.map((item) => JSON.stringify(item)).join("\n") + "\n", "utf-8");
    fs.writeFileSync(
        markerPath,
        JSON.stringify(
            {
                schema_version: "1.0.0",
                scenario: scenarioName,
                seed: String(seed),
                generated_at_utc: new Date().toISOString(),
            },
            null,
            2
        ) + "\n",
        "utf-8"
    );

    // ── Expanded dangerous preferences per scenario ──────────────────
    const groups = SCENARIO_PREF_GROUPS[scenarioName] || ['core'];
    const prefLines = [];
    for (const group of groups) {
        const prefs = DANGEROUS_PREFS[group] || [];
        for (const [key, val] of prefs) {
            const jsVal = typeof val === "string" ? `"${val}"` : val;
            prefLines.push(`user_pref("${key}", ${jsVal});`);
        }
    }
    // Always write core prefs; risky scenarios get additional groups
    if (riskySettings || prefLines.length > 0) {
        const userJs = path.join(profileDir, "user.js");
        fs.appendFileSync(userJs, "\n" + prefLines.join("\n") + "\n", "utf-8");
    }

    const prefsSignal = {
        dangerous_prefs_count: prefLines.length,
        dangerous_prefs_list: prefLines.map(l => l.replace(/^user_pref\("/, "").replace(/",.*$/, "")),
        groups_applied: groups,
    };
    appendAction(actionLog, {
        stage: "dangerous_prefs",
        status: "ok",
        ...prefsSignal,
    });
    return prefsSignal;
}

function _copyDirSync(src, dest) {
    if (!fs.existsSync(src)) return;
    safeMkdir(dest);
    for (const file of fs.readdirSync(src)) {
        const pSrc = path.join(src, file);
        const pDest = path.join(dest, file);
        if (fs.statSync(pSrc).isDirectory()) {
            _copyDirSync(pSrc, pDest);
        } else {
            fs.copyFileSync(pSrc, pDest);
        }
    }
}

function copyExtensionsFromCache(profileDir, cacheDir, actionLog) {
    const srcExt = path.join(cacheDir, "extensions");
    const destExt = path.join(profileDir, "extensions");
    const srcJson = path.join(cacheDir, "extensions.json");
    const destJson = path.join(profileDir, "extensions.json");

    if (fs.existsSync(srcExt)) _copyDirSync(srcExt, destExt);
    if (fs.existsSync(srcJson)) fs.copyFileSync(srcJson, destJson);

    let count = 0;
    try {
        if (fs.existsSync(destJson)) {
            const data = JSON.parse(fs.readFileSync(destJson, "utf8"));
            count = data.addons?.length || 0;
        }
    } catch { }

    appendAction(actionLog, {
        stage: "extension_cache_copy",
        status: "ok",
        extensions_copied: count
    });
    return { extensions_found: count, extensions_active: count };
}

function seedExtensionArtifacts(profileDir, scenarioName, rng, actionLog) {
    const extDir = path.join(profileDir, "extensions");
    safeMkdir(extDir);

    // Pick how many extensions and which templates to use
    const count = scenarioName === "adware_like" ? randInt(rng, 4, 7) : randInt(rng, 2, 5);
    const templates = pickSome(SUSPICIOUS_EXTENSION_TEMPLATES, Math.min(count, SUSPICIOUS_EXTENSION_TEMPLATES.length), rng);
    const addons = [];
    let sideloadedCount = 0;
    let unsignedCount = 0;
    let overpermissionedCount = 0;

    for (let i = 0; i < templates.length; i++) {
        const tmpl = templates[i];
        const id = `${tmpl.namePrefix.toLowerCase().replace(/\s+/g, "-")}-${crypto.randomBytes(3).toString("hex")}@foxclaw.test`;
        const addonDir = path.join(extDir, id);
        safeMkdir(addonDir);

        // Build a realistic manifest
        const manifest = {
            manifest_version: 2,
            name: `${tmpl.namePrefix} v${randInt(rng, 1, 9)}.${randInt(rng, 0, 15)}`,
            version: `${randInt(rng, 1, 5)}.${randInt(rng, 0, 20)}.${randInt(rng, 0, 99)}`,
            description: `${tmpl.namePrefix} - Enhanced browsing experience`,
            permissions: tmpl.permissions,
            browser_action: {
                default_title: tmpl.namePrefix,
                default_popup: "popup.html",
            },
            background: {
                scripts: ["background.js"],
                persistent: true,
            },
        };
        if (tmpl.content_scripts.length > 0) {
            manifest.content_scripts = tmpl.content_scripts;
        }

        fs.writeFileSync(path.join(addonDir, "manifest.json"), JSON.stringify(manifest, null, 2));

        // Write dummy background.js with suspicious patterns
        const bgJs = [
            "// Auto-generated extension background script",
            `console.log("[${tmpl.namePrefix}] loaded");`,
            tmpl.permissions.includes("webRequest") ? "chrome.webRequest.onBeforeRequest.addListener(function(details) { return {}; }, {urls: ['<all_urls>']}, ['blocking']);" : "",
            tmpl.permissions.includes("cookies") ? "chrome.cookies.getAll({}, function(cookies) { /* collect */ });" : "",
        ].filter(Boolean).join("\n");
        fs.writeFileSync(path.join(addonDir, "background.js"), bgJs);

        const isSideloaded = tmpl.sideloaded || (scenarioName === "adware_like" && chance(rng, 0.6));
        const isUnsigned = tmpl.unsigned || (scenarioName === "adware_like" && chance(rng, 0.5));
        const isOverpermissioned = tmpl.permissions.includes("<all_urls>") && tmpl.permissions.length >= 4;

        if (isSideloaded) sideloadedCount++;
        if (isUnsigned) unsignedCount++;
        if (isOverpermissioned) overpermissionedCount++;

        addons.push({
            id,
            active: true,
            signedState: isUnsigned ? 0 : 2,
            signedDate: isUnsigned ? null : new Date(Date.now() - randInt(rng, 86400000, 31536000000)).toISOString(),
            location: isSideloaded ? 16 : 1,  // 16 = sideloaded via file system, 1 = normal install
            defaultLocale: { name: manifest.name },
            sourceURI: isSideloaded ? `file:///${addonDir}` : `https://addons.mozilla.org/firefox/downloads/latest/${id}`,
            permissions: tmpl.permissions,
            type: "extension",
            installDate: new Date(Date.now() - randInt(rng, 86400000, 63072000000)).toISOString(),
            updateDate: new Date(Date.now() - randInt(rng, 3600000, 86400000)).toISOString(),
        });
    }

    const extJsonPath = path.join(profileDir, "extensions.json");
    fs.writeFileSync(extJsonPath, JSON.stringify({ addons }, null, 2));

    const signal = {
        extensions_found: addons.length,
        extensions_active: addons.length,
        sideloaded_count: sideloadedCount,
        unsigned_count: unsignedCount,
        overpermissioned_count: overpermissionedCount,
    };

    appendAction(actionLog, {
        stage: "extension_seed",
        status: "ok",
        ...signal,
    });
    return signal;
}

function seedCredentialArtifacts(profileDir, scenarioName, rng, actionLog) {
    const shouldSeed =
        scenarioName === "credential_reuse" ||
        scenarioName === "adware_like" ||
        chance(rng, 0.20);
    if (!shouldSeed) {
        appendAction(actionLog, {
            stage: "credential_seed",
            status: "skip",
            reason: "scenario_probability",
        });
        return {
            logins_present: false,
            saved_logins_count: 0,
            vulnerable_passwords_count: 0,
            dismissed_breach_alerts_count: 0,
            insecure_http_login_count: 0,
        };
    }

    const loginsPath = path.join(profileDir, "logins.json");
    const fallbackPayload = {
        nextId: 1,
        logins: [],
        disabledHosts: [],
    };

    let payload = fallbackPayload;
    if (fs.existsSync(loginsPath)) {
        try {
            const parsed = JSON.parse(fs.readFileSync(loginsPath, "utf-8"));
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
                payload = {
                    ...fallbackPayload,
                    ...parsed,
                };
            }
        } catch (err) {
            appendAction(actionLog, {
                stage: "credential_seed",
                status: "error",
                message: `unable to parse existing logins.json: ${err.message}`,
            });
            payload = fallbackPayload;
        }
    }

    if (!Array.isArray(payload.logins)) {
        payload.logins = [];
    }
    if (!Array.isArray(payload.disabledHosts)) {
        payload.disabledHosts = [];
    }

    const maxLoginId = payload.logins.reduce((acc, item) => {
        if (!item || typeof item !== "object") {
            return acc;
        }
        if (typeof item.id === "number" && Number.isInteger(item.id) && item.id > acc) {
            return item.id;
        }
        return acc;
    }, 0);
    if (
        typeof payload.nextId !== "number" ||
        !Number.isFinite(payload.nextId) ||
        !Number.isInteger(payload.nextId) ||
        payload.nextId <= 0
    ) {
        payload.nextId = maxLoginId + 1;
    } else if (payload.nextId <= maxLoginId) {
        payload.nextId = maxLoginId + 1;
    }

    const existingVulnerable = Array.isArray(payload.potentiallyVulnerablePasswords)
        ? [...payload.potentiallyVulnerablePasswords]
        : [];
    const existingDismissed =
        payload.dismissedBreachAlertsByLoginGUID &&
            typeof payload.dismissedBreachAlertsByLoginGUID === "object" &&
            !Array.isArray(payload.dismissedBreachAlertsByLoginGUID)
            ? { ...payload.dismissedBreachAlertsByLoginGUID }
            : {};

    const seededEntries =
        scenarioName === "credential_reuse" ? randInt(rng, 4, 8) : randInt(rng, 1, 4);

    // Pick weak passwords for reuse simulation
    const weakPool = pickSome(WEAK_PASSWORDS, Math.min(3, WEAK_PASSWORDS.length), rng);
    let weakPasswordCount = 0;
    let reusedPasswordCount = 0;
    const passwordBlobMap = new Map(); // track blobs for reuse detection

    for (let i = 0; i < seededEntries; i++) {
        const guid = `{${crypto.randomUUID()}}`;
        const insecure =
            scenarioName === "credential_reuse" ? chance(rng, 0.70) : chance(rng, 0.35);
        const hostname = insecure
            ? `http://legacy-auth.example.test/${scenarioName}/${i + 1}`
            : `https://auth.example.test/${scenarioName}/${i + 1}`;
        const now = Date.now() - randInt(rng, 10_000, 1_000_000);
        const usedAt = now + randInt(rng, 1_000, 60_000);

        // Decide if this entry uses a weak/reused password
        const useWeakPassword =
            scenarioName === "credential_reuse" ? chance(rng, 0.85) : chance(rng, 0.40);
        const chosenPassword = useWeakPassword
            ? weakPool[randInt(rng, 0, weakPool.length - 1)]
            : `Str0ng!${crypto.randomBytes(4).toString("hex")}`; // pragma: allowlist secret
        const passwordBlob = weakPasswordBlob(chosenPassword); // pragma: allowlist secret

        if (useWeakPassword) weakPasswordCount++;
        if (passwordBlobMap.has(passwordBlob)) {
            reusedPasswordCount++;
        }
        passwordBlobMap.set(passwordBlob, (passwordBlobMap.get(passwordBlob) || 0) + 1);

        payload.logins.push({
            id: payload.nextId,
            hostname,
            httpRealm: null,
            formSubmitURL: hostname,
            usernameField: "username",
            passwordField: "pwd", // pragma: allowlist secret
            encryptedUsername: `MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECM8synth-user${i}`,
            encryptedPassword: passwordBlob, // pragma: allowlist secret
            guid,
            encType: 1,
            timeCreated: now,
            timeLastUsed: usedAt,
            timePasswordChanged: now,
            timesUsed: randInt(rng, 1, 30),
            _foxclaw_weak: useWeakPassword,
            _foxclaw_password_hint: useWeakPassword ? chosenPassword : null,
        });
        payload.nextId += 1;

        const vulnerable =
            scenarioName === "credential_reuse" ? chance(rng, 0.90) : chance(rng, 0.45);
        if (vulnerable) {
            existingVulnerable.push({ guid });
        }

        const dismissed =
            scenarioName === "credential_reuse" ? chance(rng, 0.40) : chance(rng, 0.20);
        if (dismissed) {
            existingDismissed[guid] = { timeLastAlertShown: usedAt };
        }
    }

    payload.potentiallyVulnerablePasswords = existingVulnerable;
    payload.dismissedBreachAlertsByLoginGUID = existingDismissed;

    fs.writeFileSync(loginsPath, JSON.stringify(payload, null, 2) + "\n", "utf-8");

    const insecureHttpLoginCount = payload.logins.filter(
        (item) =>
            item &&
            typeof item === "object" &&
            typeof item.hostname === "string" &&
            item.hostname.toLowerCase().startsWith("http://")
    ).length;

    const signal = {
        logins_present: true,
        saved_logins_count: payload.logins.length,
        vulnerable_passwords_count: existingVulnerable.length,
        dismissed_breach_alerts_count: Object.keys(existingDismissed).length,
        insecure_http_login_count: insecureHttpLoginCount,
        weak_password_count: weakPasswordCount,
        reused_password_count: reusedPasswordCount,
    };

    appendAction(actionLog, {
        stage: "credential_seed",
        status: "ok",
        ...signal,
    });
    return signal;
}

// ── NEW: SQL injection / XSS form history artifacts ─────────────────────
function seedSqlInjectionArtifacts(profileDir, scenarioName, rng, actionLog) {
    const artifactDir = path.join(profileDir, "foxclaw-sim");
    safeMkdir(artifactDir);

    const sqliCount = randInt(rng, 2, 5);
    const xssCount = randInt(rng, 1, 4);
    const sqliPicked = pickSome(SQLI_PAYLOADS, Math.min(sqliCount, SQLI_PAYLOADS.length), rng);
    const xssPicked = pickSome(XSS_PAYLOADS, Math.min(xssCount, XSS_PAYLOADS.length), rng);

    const entries = [];
    const fieldNames = ["search", "q", "username", "email", "comment", "input", "query", "filter"];

    for (const payload of sqliPicked) {
        entries.push({
            fieldname: fieldNames[randInt(rng, 0, fieldNames.length - 1)],
            value: payload,
            type: "sqli",
            times_used: randInt(rng, 1, 8),
            first_used: new Date(Date.now() - randInt(rng, 86400000, 31536000000)).toISOString(),
            last_used: new Date(Date.now() - randInt(rng, 3600000, 86400000)).toISOString(),
        });
    }
    for (const payload of xssPicked) {
        entries.push({
            fieldname: fieldNames[randInt(rng, 0, fieldNames.length - 1)],
            value: payload,
            type: "xss",
            times_used: randInt(rng, 1, 5),
            first_used: new Date(Date.now() - randInt(rng, 86400000, 31536000000)).toISOString(),
            last_used: new Date(Date.now() - randInt(rng, 3600000, 86400000)).toISOString(),
        });
    }

    const outPath = path.join(artifactDir, "formhistory-payloads.json");
    fs.writeFileSync(outPath, JSON.stringify({
        schema_version: "1.0.0",
        scenario: scenarioName,
        generated_at_utc: new Date().toISOString(),
        description: "Simulated form history entries containing injection payloads for scanner validation",
        entries,
    }, null, 2) + "\n", "utf-8");

    const signal = {
        sqli_payload_count: sqliPicked.length,
        xss_payload_count: xssPicked.length,
        total_injection_entries: entries.length,
    };
    appendAction(actionLog, { stage: "injection_artifacts", status: "ok", ...signal });
    return signal;
}

// ── NEW: Insecure cookie artifacts ──────────────────────────────────────
function seedInsecureCookies(profileDir, scenarioName, rng, actionLog) {
    const artifactDir = path.join(profileDir, "foxclaw-sim");
    safeMkdir(artifactDir);

    const count = scenarioName === "credential_reuse" || scenarioName === "adware_like"
        ? randInt(rng, 4, 8)
        : randInt(rng, 2, 5);
    const picked = pickSome(INSECURE_COOKIE_TEMPLATES, Math.min(count, INSECURE_COOKIE_TEMPLATES.length), rng);
    const marker = `${Date.now()}-${randInt(rng, 1000, 9999)}`;

    const cookies = picked.map((tmpl, idx) => {
        const expiry = Date.now() + randInt(rng, 86400000, 315360000000); // up to 10 years
        return {
            name: tmpl.name,
            value: tmpl.value.replace("{MARKER}", `${marker}-${idx}`),
            domain: tmpl.domain,
            path: "/",
            secure: tmpl.secure,
            httpOnly: tmpl.httpOnly,
            sameSite: tmpl.sameSite,
            expirationDate: Math.floor(expiry / 1000),
            _foxclaw_issues: [
                !tmpl.secure ? "missing_secure_flag" : null,
                !tmpl.httpOnly ? "missing_httponly_flag" : null,
                tmpl.sameSite === "None" && !tmpl.secure ? "samesite_none_without_secure" : null,
                tmpl.domain.startsWith(".") ? "broad_domain_scope" : null,
                (expiry - Date.now()) > 157680000000 ? "excessive_expiry" : null,
            ].filter(Boolean),
        };
    });

    const outPath = path.join(artifactDir, "insecure-cookies.json");
    fs.writeFileSync(outPath, JSON.stringify({
        schema_version: "1.0.0",
        scenario: scenarioName,
        generated_at_utc: new Date().toISOString(),
        cookies,
    }, null, 2) + "\n", "utf-8");

    const missingSecure = cookies.filter(c => !c.secure).length;
    const missingHttpOnly = cookies.filter(c => !c.httpOnly).length;
    const badSameSite = cookies.filter(c => c.sameSite === "None" && !c.secure).length;

    const signal = {
        insecure_cookies_count: cookies.length,
        missing_secure_count: missingSecure,
        missing_httponly_count: missingHttpOnly,
        samesite_none_insecure_count: badSameSite,
    };
    appendAction(actionLog, { stage: "insecure_cookies", status: "ok", ...signal });
    return signal;
}

// ── NEW: Certificate exception artifacts ────────────────────────────────
function seedCertOverrides(profileDir, scenarioName, rng, actionLog) {
    const count = scenarioName === "adware_like" || scenarioName === "privacy_weak"
        ? randInt(rng, 3, 6)
        : randInt(rng, 1, 3);
    const picked = pickSome(CERT_OVERRIDE_HOSTS, Math.min(count, CERT_OVERRIDE_HOSTS.length), rng);

    // Firefox cert_override.txt format:
    // host:port<TAB>OID<TAB>dbKey<TAB>flags
    const lines = [
        "# PSM Certificate Override Settings file",
        "# This is a generated file!  Do not edit.",
    ];
    for (const entry of picked) {
        const fakeOID = `OID.2.16.840.1.101.3.4.2.1`;
        const fakeDbKey = crypto.randomBytes(20).toString("base64");
        lines.push(`${entry.host}:${entry.port}\t${fakeOID}\t${fakeDbKey}\t${entry.flags}`);
    }

    const certOverridePath = path.join(profileDir, "cert_override.txt");
    fs.writeFileSync(certOverridePath, lines.join("\n") + "\n", "utf-8");

    const signal = {
        cert_exceptions_count: picked.length,
        exceptions: picked.map(e => ({ host: e.host, port: e.port, reason: e.reason })),
    };
    appendAction(actionLog, { stage: "cert_overrides", status: "ok", ...signal });
    return signal;
}

// ── NEW: Form autofill / PII artifacts ──────────────────────────────────
function seedAutofillArtifacts(profileDir, scenarioName, rng, actionLog) {
    const count = scenarioName === "credential_reuse" ? randInt(rng, 5, 10) : randInt(rng, 2, 6);
    const picked = pickSome(AUTOFILL_PII_TEMPLATES, Math.min(count, AUTOFILL_PII_TEMPLATES.length), rng);

    const profiles = [{
        guid: `{${crypto.randomUUID()}}`,
        timeCreated: Date.now() - randInt(rng, 86400000, 31536000000),
        timeLastModified: Date.now() - randInt(rng, 3600000, 86400000),
        timesUsed: randInt(rng, 1, 50),
        fields: {},
    }];

    let sensitiveFieldCount = 0;
    for (const tmpl of picked) {
        profiles[0].fields[tmpl.fieldName] = tmpl.value;
        if (tmpl.sensitive) sensitiveFieldCount++;
    }

    const autofillPath = path.join(profileDir, "autofill-profiles.json");
    fs.writeFileSync(autofillPath, JSON.stringify({
        schema_version: "1.0.0",
        scenario: scenarioName,
        generated_at_utc: new Date().toISOString(),
        profiles,
    }, null, 2) + "\n", "utf-8");

    const signal = {
        autofill_entries_count: picked.length,
        sensitive_pii_fields_count: sensitiveFieldCount,
    };
    appendAction(actionLog, { stage: "autofill_pii", status: "ok", ...signal });
    return signal;
}

// ══════════════════════════════════════════════════════════════════════════
// Phase 0: Lifecycle Artifacts — files FoxClaw's artifacts.py collector reads
// ══════════════════════════════════════════════════════════════════════════

function writeCompatibilityIni(profileDir, rng, actionLog) {
    const versions = [
        { ver: "115.18.0", buildId: "20250113182935", osabi: "Windows_NT_x86_64-msvc" },
        { ver: "128.6.0esr", buildId: "20250128125804", osabi: "Windows_NT_x86_64-msvc" },
        { ver: "115.20.0", buildId: "20250310094223", osabi: "Windows_NT_x86_64-msvc" },
    ];
    const pick = versions[randInt(rng, 0, versions.length - 1)];
    const content = [
        "[Compatibility]",
        `LastVersion=${pick.ver}_${pick.buildId}/20250101000000`,
        `LastOSABI=${pick.osabi}`,
        `LastPlatformDir=C:\\Program Files\\Mozilla Firefox`,
        `LastAppDir=C:\\Program Files\\Mozilla Firefox\\browser`,
        "",
    ].join("\n");
    fs.writeFileSync(path.join(profileDir, "compatibility.ini"), content, "utf-8");
    appendAction(actionLog, { stage: "compatibility_ini", status: "ok", version: pick.ver });
}

function writeContainersJson(profileDir, actionLog) {
    const payload = {
        version: 4,
        lastUserContextId: 4,
        identities: [
            { userContextId: 1, public: true, icon: "fingerprint", color: "blue", l10nID: "userContextPersonal.label", accessKey: "userContextPersonal.accesskey" },
            { userContextId: 2, public: true, icon: "briefcase", color: "orange", l10nID: "userContextWork.label", accessKey: "userContextWork.accesskey" },
            { userContextId: 3, public: true, icon: "dollar", color: "green", l10nID: "userContextBanking.label", accessKey: "userContextBanking.accesskey" },
            { userContextId: 4, public: true, icon: "cart", color: "pink", l10nID: "userContextShopping.label", accessKey: "userContextShopping.accesskey" },
        ],
    };
    fs.writeFileSync(path.join(profileDir, "containers.json"), JSON.stringify(payload, null, 2) + "\n", "utf-8");
    appendAction(actionLog, { stage: "containers_json", status: "ok", identities_count: 4 });
}

function writeHandlersJson(profileDir, actionLog) {
    const payload = {
        defaultHandlersVersion: { "en-US": 4 },
        mimeTypes: {
            "application/pdf": { action: 3, ask: false },
            "text/xml": { action: 0, ask: true },
            "application/xhtml+xml": { action: 0, ask: false },
        },
        schemes: {
            mailto: { action: 4, ask: true },
            webcal: { action: 4, ask: true },
            ircs: { action: 4, ask: true },
        },
    };
    fs.writeFileSync(path.join(profileDir, "handlers.json"), JSON.stringify(payload, null, 2) + "\n", "utf-8");
    appendAction(actionLog, { stage: "handlers_json", status: "ok", mime_types: 3, schemes: 3 });
}

function writeTimesJson(profileDir, rng, actionLog) {
    const daysAgo = randInt(rng, 30, 365);
    const created = Date.now() - daysAgo * 86400000;
    const firstUse = created + randInt(rng, 60000, 3600000);
    const payload = { created, firstUse };
    fs.writeFileSync(path.join(profileDir, "times.json"), JSON.stringify(payload) + "\n", "utf-8");
    appendAction(actionLog, { stage: "times_json", status: "ok", days_ago: daysAgo });
}

function writePkcs11Txt(profileDir, actionLog) {
    const content = [
        "library=",
        "name=NSS Internal PKCS #11 Module",
        "parameters=configdir='sql:.' certPrefix='' keyPrefix='' secmod='secmod.db' flags=optimizeSpace updatedir='' updateCertPrefix='' updateKeyPrefix='' updateid='' updateTokenDescription=''",
        "NSS=Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512] askpw=any timeout=30})",
        "",
    ].join("\n");
    fs.writeFileSync(path.join(profileDir, "pkcs11.txt"), content, "utf-8");
    appendAction(actionLog, { stage: "pkcs11_txt", status: "ok" });
}

// ══════════════════════════════════════════════════════════════════════════
// Missing SQLite databases — FoxClaw runs PRAGMA quick_check on all of these
// ══════════════════════════════════════════════════════════════════════════

function seedContentPrefsDatabase(profileDir, rng, actionLog) {
    const dbPath = path.join(profileDir, "content-prefs.sqlite");
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(`
        CREATE TABLE IF NOT EXISTS prefs (id INTEGER PRIMARY KEY, groupID INTEGER, settingID INTEGER, value BLOB);
        CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    `);
    const sites = ["www.example.com", "news.ycombinator.com", "github.com", "stackoverflow.com"];
    const insertGroup = db.prepare("INSERT OR IGNORE INTO groups (name) VALUES (?)");
    const insertSetting = db.prepare("INSERT OR IGNORE INTO settings (name) VALUES (?)");
    const insertPref = db.prepare("INSERT OR IGNORE INTO prefs (groupID, settingID, value) VALUES (?, ?, ?)");
    const txn = db.transaction(() => {
        insertSetting.run("browser.content.full-zoom");
        const settingId = db.prepare("SELECT id FROM settings WHERE name = ?").get("browser.content.full-zoom").id;
        const picked = pickSome(sites, randInt(rng, 1, sites.length), rng);
        for (const site of picked) {
            insertGroup.run(site);
            const groupId = db.prepare("SELECT id FROM groups WHERE name = ?").get(site).id;
            const zoom = [0.8, 0.9, 1.0, 1.1, 1.2, 1.5][randInt(rng, 0, 5)];
            insertPref.run(groupId, settingId, zoom);
        }
    });
    txn();
    db.close();
    appendAction(actionLog, { stage: "content_prefs_db", status: "ok" });
}

function seedPermissionsDatabase(profileDir, rng, actionLog) {
    const dbPath = path.join(profileDir, "permissions.sqlite");
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(`
        CREATE TABLE IF NOT EXISTS moz_perms (
            id INTEGER PRIMARY KEY, origin TEXT, type TEXT, permission INTEGER,
            expireType INTEGER, expireTime INTEGER, modificationTime INTEGER
        );
    `);
    const perms = [
        { origin: "https://meet.google.com", type: "camera", perm: 1 },
        { origin: "https://meet.google.com", type: "microphone", perm: 1 },
        { origin: "https://www.youtube.com", type: "desktop-notification", perm: 1 },
        { origin: "https://calendar.google.com", type: "desktop-notification", perm: 1 },
        { origin: "http://192.168.1.1", type: "login-saving", perm: 2 },
        { origin: "https://maps.google.com", type: "geo", perm: 1 },
    ];
    const picked = pickSome(perms, randInt(rng, 2, perms.length), rng);
    const insert = db.prepare("INSERT INTO moz_perms (origin, type, permission, expireType, expireTime, modificationTime) VALUES (?, ?, ?, 0, 0, ?)");
    const txn = db.transaction(() => {
        for (const p of picked) insert.run(p.origin, p.type, p.perm, Date.now());
    });
    txn();
    db.close();
    appendAction(actionLog, { stage: "permissions_db", status: "ok", entries: picked.length });
}

function seedProtectionsDatabase(profileDir, actionLog) {
    const dbPath = path.join(profileDir, "protections.sqlite");
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(`
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, type INTEGER, count INTEGER,
            timestamp INTEGER, host TEXT
        );
    `);
    db.close();
    appendAction(actionLog, { stage: "protections_db", status: "ok" });
}

function seedFaviconsDatabase(profileDir, actionLog) {
    const dbPath = path.join(profileDir, "favicons.sqlite");
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(`
        CREATE TABLE IF NOT EXISTS moz_icons (
            id INTEGER PRIMARY KEY, icon_url TEXT NOT NULL, fixed_icon_url_hash INTEGER NOT NULL,
            width INTEGER NOT NULL DEFAULT 0, root INTEGER NOT NULL DEFAULT 0,
            color INTEGER, expire_ms INTEGER NOT NULL DEFAULT 0, data BLOB
        );
        CREATE TABLE IF NOT EXISTS moz_pages_w_icons (
            id INTEGER PRIMARY KEY, page_url TEXT NOT NULL, page_url_hash INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS moz_icons_to_pages (icon_id INTEGER NOT NULL, page_id INTEGER NOT NULL, expire_ms INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (icon_id, page_id));
    `);
    db.close();
    appendAction(actionLog, { stage: "favicons_db", status: "ok" });
}

function writeManifest(manifestPath, payload) {
    safeMkdir(path.dirname(manifestPath));
    fs.writeFileSync(manifestPath, JSON.stringify(payload, null, 2) + "\n", "utf-8");
}

async function main() {
    let parsed;
    try {
        parsed = parseArgs(process.argv.slice(2));
    } catch (err) {
        console.error(err.message);
        process.exit(2);
    }

    const { profileDir, scenario: scenarioArg, seed, profileName, manifestOut, fast, extensionsCache, jsonlLog, buildCache } = parsed;
    if (!fs.existsSync(profileDir)) {
        console.error(`profileDir not found: ${profileDir}`);
        process.exit(2);
    }

    FAST_MODE = fast;
    if (jsonlLog) {
        JSONL_PROFILE = profileName;
        JSONL_SCENARIO = scenarioArg;
        JSONL_STREAM = fs.createWriteStream(jsonlLog, { flags: "a" });
    }

    const rng = makeRng(seed);
    const selected = selectScenario(scenarioArg, rng);
    const scenarioName = selected.name;
    const scenarioConfig = selected.config;
    const actionLog = [];
    const startedAt = Date.now();

    appendAction(actionLog, {
        stage: "start",
        status: "ok",
        scenario: scenarioName,
        seed: String(seed),
        profile_name: profileName,
        fast_mode: FAST_MODE,
        build_cache: buildCache,
    });

    if (buildCache) {
        seedExtensionArtifacts(profileDir, scenarioName, rng, actionLog);
        const manifestPayload = {
            schema_version: "1.0.0",
            profile_dir: path.resolve(profileDir),
            profile_name: profileName,
            scenario: scenarioName,
            seed: String(seed),
            started_at_utc: new Date(startedAt).toISOString(),
            completed_at_utc: new Date().toISOString(),
            runtime_seconds: Number(((Date.now() - startedAt) / 1000).toFixed(3)),
            actions_total: actionLog.length,
            action_stage_counts: summarizeStages(actionLog),
            actions: actionLog,
        };
        writeManifest(manifestOut || path.join(profileDir, "foxclaw-sim-metadata.json"), manifestPayload);
        if (JSONL_STREAM) JSONL_STREAM.end();
        console.log(`[+] mutate_profile built extension cache at ${profileDir}`);
        process.exit(0);
    }
    // ══════════════════════════════════════════════════════════════════
    // PHASE 0: Lifecycle artifacts — files FoxClaw's artifact collector reads
    // ══════════════════════════════════════════════════════════════════

    writeCompatibilityIni(profileDir, rng, actionLog);
    writeContainersJson(profileDir, actionLog);
    writeHandlersJson(profileDir, actionLog);
    writeTimesJson(profileDir, rng, actionLog);
    writePkcs11Txt(profileDir, actionLog);

    // ══════════════════════════════════════════════════════════════════
    // PHASE 1: Write all security signal artifacts (direct file writes)
    // ══════════════════════════════════════════════════════════════════

    const prefsSignals = writeScenarioArtifacts(profileDir, scenarioName, seed, scenarioConfig.risky_settings, actionLog);
    const credentialSignals = seedCredentialArtifacts(profileDir, scenarioName, rng, actionLog);

    let extensionSignals;
    if (extensionsCache) {
        extensionSignals = copyExtensionsFromCache(profileDir, extensionsCache, actionLog);
    } else {
        extensionSignals = seedExtensionArtifacts(profileDir, scenarioName, rng, actionLog);
    }

    let certSignals = { cert_exceptions_count: 0 };
    if (chance(rng, scenarioConfig.cert_override_rate)) {
        certSignals = seedCertOverrides(profileDir, scenarioName, rng, actionLog);
    }

    let autofillSignals = { autofill_entries_count: 0, sensitive_pii_fields_count: 0 };
    if (chance(rng, scenarioConfig.autofill_rate)) {
        autofillSignals = seedAutofillArtifacts(profileDir, scenarioName, rng, actionLog);
    }

    // ══════════════════════════════════════════════════════════════════
    // PHASE 2: Write to Firefox's real SQLite databases
    // ══════════════════════════════════════════════════════════════════

    const historySignals = seedBrowsingHistory(profileDir, scenarioName, rng, actionLog);

    let cookieSignals = { cookies_db_entries: 0, missing_secure: 0, missing_httponly: 0 };
    if (chance(rng, scenarioConfig.insecure_cookie_rate)) {
        cookieSignals = seedCookiesDatabase(profileDir, scenarioName, rng, actionLog);
    }

    let formHistorySignals = { sqli_payload_count: 0, xss_payload_count: 0, total_formhistory_entries: 0 };
    if (chance(rng, scenarioConfig.sqli_rate)) {
        formHistorySignals = seedFormHistoryDatabase(profileDir, scenarioName, rng, actionLog);
    }

    // Additional SQLite databases FoxClaw runs PRAGMA quick_check against
    seedContentPrefsDatabase(profileDir, rng, actionLog);
    seedPermissionsDatabase(profileDir, rng, actionLog);
    seedProtectionsDatabase(profileDir, actionLog);
    seedFaviconsDatabase(profileDir, actionLog);

    appendAction(actionLog, { stage: "all_phases_complete", status: "ok" });

    // ══════════════════════════════════════════════════════════════════
    // PHASE 3: Write manifest with all signals
    // ══════════════════════════════════════════════════════════════════

    const completedAt = Date.now();
    const manifestPayload = {
        schema_version: "4.0.0",
        profile_dir: path.resolve(profileDir),
        profile_name: profileName,
        scenario: scenarioName,
        requested_scenario: scenarioArg,
        seed: String(seed),
        fast_mode: FAST_MODE,
        config_hash: computeConfigHash(),
        engine: "sqlite",
        started_at_utc: new Date(startedAt).toISOString(),
        completed_at_utc: new Date(completedAt).toISOString(),
        runtime_seconds: Number(((completedAt - startedAt) / 1000).toFixed(3)),
        actions_total: actionLog.length,
        action_stage_counts: summarizeStages(actionLog),
        expected_scan_signals: {
            credentials: credentialSignals,
            extensions: extensionSignals,
            preferences: prefsSignals,
            browsing_history: historySignals,
            cookies: cookieSignals,
            injection_artifacts: formHistorySignals,
            certificates: certSignals,
            form_data: autofillSignals,
        },
        actions: actionLog,
    };

    const defaultManifestOut = path.join(profileDir, "foxclaw-sim-metadata.json");
    writeManifest(manifestOut || defaultManifestOut, manifestPayload);
    console.log(
        `[+] mutate_profile completed profile=${profileName} scenario=${scenarioName} engine=sqlite seed=${seed} signals=${Object.keys(manifestPayload.expected_scan_signals).length}`
    );

    if (JSONL_STREAM) {
        JSONL_STREAM.end();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
