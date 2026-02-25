import { firefox } from "playwright";
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

const ALLOWED_DOMAINS = new Set([
    "duckduckgo.com",
    "en.wikipedia.org",
    "news.ycombinator.com",
    "httpbin.org",
    "example.com",
    "www.openstreetmap.org",
    "www.reuters.com",
    "www.nytimes.com",
    "www.cnet.com",
    "www.techradar.com",
    "www.majorgeeks.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "www.eff.org",
    "privacyinternational.org",
    "pastebin.com",
    "ghostbin.com"
]);

function assertAllowedUrl(urlStr) {
    try {
        const u = new URL(urlStr);
        let allowed = false;
        for (const domain of ALLOWED_DOMAINS) {
            if (u.hostname === domain || u.hostname.endsWith(`.${domain}`)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) throw new Error(`URL ${urlStr} not in allowlist`);
    } catch (e) {
        throw new Error(`Invalid or blocked URL: ${urlStr} - ${e.message}`);
    }
}

async function retryGoto(page, url, options, maxRetries = 2) {
    assertAllowedUrl(url);
    if (FAST_MODE && (!options || !options.timeout)) {
        options = { ...options, timeout: 5000 };
    }
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            await page.goto(url, options);
            return;
        } catch (err) {
            if (attempt === maxRetries) throw err;
            await sleep(1000 * (attempt + 1));
        }
    }
}

function computeConfigHash() {
    const configData = JSON.stringify({
        // Minimal set to detect major drift; can extend later
        allowedDomains: [...ALLOWED_DOMAINS].sort()
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

async function tryClickFirst(page, selectors) {
    for (const selector of selectors) {
        const loc = page.locator(selector).first();
        try {
            if (await loc.count()) {
                await loc.click({ timeout: 1500 });
                return true;
            }
        } catch {
            // Ignore selector misses and continue trying alternatives.
        }
    }
    return false;
}

async function wanderSites(context, scenarioConfig, rng, actionLog) {
    const siteCount = randInt(rng, scenarioConfig.site_min, scenarioConfig.site_max);
    const urlPool = [...BASE_URL_POOL, ...scenarioConfig.extra_urls];
    const chosen = pickSome(urlPool, Math.min(siteCount, urlPool.length), rng);
    const pages = [];

    for (const url of chosen) {
        const page = await context.newPage();
        pages.push(page);
        try {
            await retryGoto(page, url, { waitUntil: "domcontentloaded", timeout: 30000 });
            appendAction(actionLog, { stage: "navigate", status: "ok", url });

            const scrollLoops = randInt(rng, 1, 4);
            for (let idx = 0; idx < scrollLoops; idx++) {
                await page.mouse.wheel(0, randInt(rng, 400, 1800));
                await sleep(randInt(rng, 350, 900));
            }

            const clicked = await tryClickFirst(page, [
                "a:visible",
                "h2 a:visible",
                "h3 a:visible",
                "article a:visible",
            ]);
            appendAction(actionLog, {
                stage: "click",
                status: clicked ? "ok" : "skip",
                url,
            });

            await sleep(randInt(rng, 600, 1800));
            if (chance(rng, 0.35)) {
                await page.goBack({ timeout: 4000 }).catch(() => null);
                appendAction(actionLog, { stage: "back", status: "ok", url });
            }
        } catch (err) {
            appendAction(actionLog, {
                stage: "navigate",
                status: "error",
                url,
                message: err.message,
            });
        }
    }

    for (let i = 1; i < pages.length; i++) {
        if (chance(rng, 0.5)) {
            try {
                await pages[i].close();
                appendAction(actionLog, { stage: "tab_close", status: "ok", index: i });
            } catch (err) {
                appendAction(actionLog, { stage: "tab_close", status: "error", index: i, message: err.message });
            }
        }
    }
}

async function simulateSearches(context, rng, actionLog) {
    const page = await context.newPage();
    const count = randInt(rng, 1, 3);
    try {
        await retryGoto(page, "https://duckduckgo.com/", { waitUntil: "domcontentloaded", timeout: 20000 });
        for (let i = 0; i < count; i++) {
            const term = SEARCH_TERMS[randInt(rng, 0, SEARCH_TERMS.length - 1)];
            await page.fill("input[name='q']", term);
            await page.keyboard.press("Enter");
            await page.waitForLoadState("domcontentloaded", { timeout: 6000 }).catch(() => null);
            await sleep(randInt(rng, 500, 1200));
            await tryClickFirst(page, ["a[data-testid='result-title-a']:visible", "h2 a:visible", "a:visible"]);
            appendAction(actionLog, { stage: "search", status: "ok", term });
            await sleep(randInt(rng, 400, 1200));
            await retryGoto(page, "https://duckduckgo.com/", { waitUntil: "domcontentloaded", timeout: 10000 }).catch(() => null);
        }
    } catch (err) {
        appendAction(actionLog, { stage: "search", status: "error", message: err.message });
    } finally {
        await page.close().catch(() => null);
    }
}

async function simulateFormSubmissions(context, rng, actionLog) {
    const attempts = randInt(rng, 1, 3);
    for (let i = 0; i < attempts; i++) {
        if (chance(rng, 0.55)) {
            const page = await context.newPage();
            try {
                await retryGoto(page, "https://news.ycombinator.com/login", { waitUntil: "domcontentloaded", timeout: 15000 });
                await page.fill("input[name='acct']", `user_${Date.now()}_${randInt(rng, 100, 999)}`);
                await page.fill("input[name='pw']", "password123!");
                await page.click("input[value='login']", { timeout: 5000 });
                appendAction(actionLog, { stage: "form_login", status: "ok", provider: "hn" });
                await sleep(randInt(rng, 600, 1500));
            } catch (err) {
                appendAction(actionLog, { stage: "form_login", status: "error", provider: "hn", message: err.message });
            } finally {
                await page.close().catch(() => null);
            }
        } else {
            const page = await context.newPage();
            try {
                await retryGoto(page, "https://httpbin.org/forms/post", { waitUntil: "domcontentloaded", timeout: 20000 });
                await page.fill("input[name='custname']", `Alex ${randInt(rng, 10, 99)}`);
                await page.fill("input[name='custtel']", `555-010${randInt(rng, 0, 9)}`);
                await page.fill("input[name='custemail']", `foxclaw${randInt(rng, 100, 999)}@example.com`);
                await page.fill("textarea[name='comments']", "Browser profile simulation for security testing.");
                await page.click("button[type='submit']", { timeout: 6000 });
                appendAction(actionLog, { stage: "form_submission", status: "ok", provider: "httpbin" });
                await sleep(randInt(rng, 700, 1500));
            } catch (err) {
                appendAction(actionLog, {
                    stage: "form_submission",
                    status: "error",
                    provider: "httpbin",
                    message: err.message,
                });
            } finally {
                await page.close().catch(() => null);
            }
        }
    }
}

async function simulateDownloads(context, profileDir, rng, actionLog) {
    const count = randInt(rng, 1, 3);
    const downloadsDir = path.join(profileDir, "Downloads");
    safeMkdir(downloadsDir);

    for (let idx = 0; idx < count; idx++) {
        const filename = DOWNLOAD_NAMES[randInt(rng, 0, DOWNLOAD_NAMES.length - 1)];
        const page = await context.newPage();
        try {
            await retryGoto(page, "https://example.com/", { waitUntil: "domcontentloaded", timeout: 15000 });
            const [download] = await Promise.all([
                page.waitForEvent("download", { timeout: 7000 }),
                page.evaluate((name) => {
                    const lines = [
                        "FoxClaw Windows profile simulation artifact",
                        `filename=${name}`,
                        `created_at=${new Date().toISOString()}`,
                        "classification=synthetic",
                    ];
                    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain" });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = name;
                    document.body.appendChild(link);
                    link.click();
                    link.remove();
                    URL.revokeObjectURL(url);
                }, filename),
            ]);
            const outPath = path.join(downloadsDir, `${Date.now()}-${filename}`);
            await download.saveAs(outPath);
            appendAction(actionLog, { stage: "download", status: "ok", filename: path.basename(outPath) });
            await sleep(randInt(rng, 300, 900));
        } catch (err) {
            appendAction(actionLog, { stage: "download", status: "error", filename, message: err.message });
        } finally {
            await page.close().catch(() => null);
        }
    }
}

async function simulatePermissions(context, rng, actionLog) {
    const page = await context.newPage();
    try {
        await page.goto("https://www.openstreetmap.org/", { waitUntil: "domcontentloaded", timeout: 20000 });
        await page.evaluate(async () => {
            try {
                if ("Notification" in window) {
                    await Notification.requestPermission();
                }
            } catch {
                // Ignore browser policy failures.
            }
            try {
                navigator.geolocation.getCurrentPosition(() => { }, () => { });
            } catch {
                // Ignore browser policy failures.
            }
        });
        appendAction(actionLog, { stage: "permissions", status: "ok", origin: "openstreetmap.org" });
        await sleep(randInt(rng, 600, 1500));
    } catch (err) {
        appendAction(actionLog, { stage: "permissions", status: "error", message: err.message });
    } finally {
        await page.close().catch(() => null);
    }
}

async function simulateStorageArtifacts(context, rng, actionLog) {
    const page = await context.newPage();
    try {
        await page.goto("https://example.com/", { waitUntil: "domcontentloaded", timeout: 15000 });
        const token = `${Date.now()}-${randInt(rng, 1000, 9999)}`;
        await page.evaluate(async (marker) => {
            localStorage.setItem("foxclaw_last_campaign", `campaign-${marker}`);
            localStorage.setItem("foxclaw_plugin_state", "enabled");
            sessionStorage.setItem("foxclaw_temp_notice", "update-required");
            document.cookie = `fc_session=${marker}; path=/; SameSite=Lax`;
            document.cookie = "fc_pref=tracking-enabled; path=/";

            const request = indexedDB.open("foxclaw-sim-db", 1);
            await new Promise((resolve, reject) => {
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains("events")) {
                        db.createObjectStore("events", { keyPath: "id" });
                    }
                };
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
            const db = request.result;
            const tx = db.transaction("events", "readwrite");
            tx.objectStore("events").put({
                id: `evt-${marker}`,
                type: "notification_prompt",
                timestamp: Date.now(),
            });
            await new Promise((resolve, reject) => {
                tx.oncomplete = () => resolve();
                tx.onerror = () => reject(tx.error);
                tx.onabort = () => reject(tx.error);
            });
            db.close();
        }, token);
        appendAction(actionLog, { stage: "storage", status: "ok", marker: token });
    } catch (err) {
        appendAction(actionLog, { stage: "storage", status: "error", message: err.message });
    } finally {
        await page.close().catch(() => null);
    }
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

    if (riskySettings) {
        const userJs = path.join(profileDir, "user.js");
        const lines = [
            'user_pref("privacy.clearOnShutdown.cookies", false);',
            'user_pref("signon.autofillForms", true);',
            'user_pref("network.cookie.lifetimePolicy", 0);',
            'user_pref("extensions.autoDisableScopes", 0);',
        ];
        fs.appendFileSync(userJs, "\n" + lines.join("\n") + "\n", "utf-8");
    }
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
    const count = randInt(rng, 2, 5);
    const addons = [];

    for (let i = 0; i < count; i++) {
        const id = `ext_${crypto.randomBytes(4).toString("hex")}@example.com`;
        const addonDir = path.join(extDir, id);
        safeMkdir(addonDir);
        fs.writeFileSync(
            path.join(addonDir, "manifest.json"),
            JSON.stringify({ manifest_version: 2, name: `Synthed Ext ${i}`, version: "1.0", browser_action: {} })
        );
        addons.push({
            id,
            active: true,
            defaultLocale: { name: `Synthed Ext ${i}` },
            sourceURI: `file:///${addonDir}`
        });
    }

    const extJsonPath = path.join(profileDir, "extensions.json");
    fs.writeFileSync(extJsonPath, JSON.stringify({ addons }, null, 2));

    appendAction(actionLog, {
        stage: "extension_seed",
        status: "ok",
        extensions_seeded: count
    });
    return { extensions_found: count, extensions_active: count };
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
        scenarioName === "credential_reuse" ? randInt(rng, 3, 6) : randInt(rng, 1, 3);
    for (let i = 0; i < seededEntries; i++) {
        const guid = `{${crypto.randomUUID()}}`;
        const insecure =
            scenarioName === "credential_reuse" ? chance(rng, 0.70) : chance(rng, 0.35);
        const hostname = insecure
            ? `http://legacy-auth.example.test/${scenarioName}/${i + 1}`
            : `https://auth.example.test/${scenarioName}/${i + 1}`;
        const now = Date.now() - randInt(rng, 10_000, 1_000_000);
        const usedAt = now + randInt(rng, 1_000, 60_000);

        payload.logins.push({
            id: payload.nextId,
            hostname,
            httpRealm: null,
            formSubmitURL: hostname,
            usernameField: "username",
            passwordField: "pwd", // pragma: allowlist secret
            encryptedUsername: "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECM8synth-user",
            encryptedPassword: "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECM8synth-token", // pragma: allowlist secret
            guid,
            encType: 1,
            timeCreated: now,
            timeLastUsed: usedAt,
            timePasswordChanged: now,
            timesUsed: randInt(rng, 1, 12),
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
    };

    appendAction(actionLog, {
        stage: "credential_seed",
        status: "ok",
        ...signal,
    });
    return signal;
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

    const { profileDir, scenario: scenarioArg, seed, profileName, manifestOut, fast, extensionsCache, jsonlLog } = parsed;
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

    let context;
    try {
        context = await firefox.launchPersistentContext(profileDir, {
            headless: true,
            acceptDownloads: true,
            viewport: {
                width: randInt(rng, 1200, 1680),
                height: randInt(rng, 720, 1050),
            },
            colorScheme: chance(rng, 0.5) ? "light" : "dark",
        });
    } catch (err) {
        console.error(`failed to launch persistent context: ${err.message}`);
        process.exit(1);
    }

    try {
        await wanderSites(context, scenarioConfig, rng, actionLog);
        await simulateSearches(context, rng, actionLog);
        if (chance(rng, scenarioConfig.login_rate) || chance(rng, scenarioConfig.form_rate)) {
            await simulateFormSubmissions(context, rng, actionLog);
        }
        if (chance(rng, scenarioConfig.download_rate)) {
            await simulateDownloads(context, profileDir, rng, actionLog);
        }
        if (chance(rng, scenarioConfig.permissions_rate)) {
            await simulatePermissions(context, rng, actionLog);
        }
        if (chance(rng, scenarioConfig.storage_rate)) {
            await simulateStorageArtifacts(context, rng, actionLog);
        }
        await sleep(randInt(rng, 700, 1800));
    } finally {
        await context.close().catch(() => null);
    }

    writeScenarioArtifacts(profileDir, scenarioName, seed, scenarioConfig.risky_settings, actionLog);
    const credentialSignals = seedCredentialArtifacts(profileDir, scenarioName, rng, actionLog);

    let extensionSignals;
    if (extensionsCache) {
        extensionSignals = copyExtensionsFromCache(profileDir, extensionsCache, actionLog);
    } else {
        extensionSignals = seedExtensionArtifacts(profileDir, scenarioName, rng, actionLog);
    }

    const completedAt = Date.now();
    const manifestPayload = {
        schema_version: "1.0.0",
        profile_dir: path.resolve(profileDir),
        profile_name: profileName,
        scenario: scenarioName,
        requested_scenario: scenarioArg,
        seed: String(seed),
        fast_mode: FAST_MODE,
        config_hash: computeConfigHash(),
        started_at_utc: new Date(startedAt).toISOString(),
        completed_at_utc: new Date(completedAt).toISOString(),
        runtime_seconds: Number(((completedAt - startedAt) / 1000).toFixed(3)),
        actions_total: actionLog.length,
        action_stage_counts: summarizeStages(actionLog),
        expected_scan_signals: {
            credentials: credentialSignals,
            extensions: extensionSignals,
        },
        actions: actionLog,
    };

    const defaultManifestOut = path.join(profileDir, "foxclaw-sim-metadata.json");
    writeManifest(manifestOut || defaultManifestOut, manifestPayload);
    console.log(
        `[+] mutate_profile completed profile=${profileName} scenario=${scenarioName} seed=${seed} hash=${manifestPayload.config_hash}`
    );

    if (JSONL_STREAM) {
        JSONL_STREAM.end();
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
