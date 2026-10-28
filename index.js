const Express = require("express");
const express = Express();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

express.use(Express.json());
express.use(Express.urlencoded({ extended: true }));
express.use(Express.static("public"));
express.use(cookieParser());

const FRONTEND_URL = (process.env.FRONTEND_URL || "http://localhost:8080").replace(/\/$/, "");
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const DISCORD_CALLBACK_URL = process.env.DISCORD_CALLBACK_URL || "https://p01--lawinserver--wxsd2297cwp7.code.run/auth/discord/callback";
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "none", path: "/" };

function sign(value) {
    return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}
function safeEqual(a, b) {
    const left = Buffer.from(String(a || ""));
    const right = Buffer.from(String(b || ""));
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function readSession(req) {
    if (!SESSION_SECRET) return null;
    const token = req.cookies && req.cookies.flipped_session;
    if (!token || !token.includes(".")) return null;
    const [payload, signature] = token.split(".");
    if (!safeEqual(signature, sign(payload))) return null;
    try {
        const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
        if (!session.exp || session.exp < Math.floor(Date.now() / 1000) || !session.user) return null;
        return session.user;
    } catch { return null; }
}
function setSessionCookie(res, user) {
    const payload = Buffer.from(JSON.stringify({
        user,
        exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS
    })).toString("base64url");
    res.cookie("flipped_session", payload + "." + sign(payload), {
        ...COOKIE_OPTIONS,
        maxAge: SESSION_MAX_AGE_SECONDS * 1000
    });
}

// Public status endpoints; authentication endpoints use credentialed, origin-restricted CORS.
express.use((req, res, next) => {
    if (req.path.startsWith("/auth/")) {
        const origin = req.get("Origin");
        if (origin === FRONTEND_URL) {
            res.set("Access-Control-Allow-Origin", FRONTEND_URL);
            res.set("Access-Control-Allow-Credentials", "true");
            res.set("Vary", "Origin");
        }
        res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Content-Type");
        if (req.method === "OPTIONS") return res.sendStatus(204);
    } else if (req.path === "/api/health" || req.path === "/fortnite/api/version") {
        res.set("Access-Control-Allow-Origin", "*");
        res.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Content-Type");
        if (req.method === "OPTIONS") return res.sendStatus(204);
    }
    next();
});

express.get("/api/health", (req, res) => {
    res.status(200).json({ status: "ok", service: "lawinserver" });
});

// Redirect users to Discord. OAuth state is checked on callback to reduce CSRF risk.
express.get("/auth/discord", (req, res) => {
    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !SESSION_SECRET) {
        return res.status(503).send("Discord login is not configured on the server yet.");
    }
    const state = crypto.randomBytes(32).toString("hex");
    res.cookie("flipped_oauth_state", state, { ...COOKIE_OPTIONS, maxAge: 10 * 60 * 1000 });
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: DISCORD_CALLBACK_URL,
        response_type: "code",
        scope: "identify",
        state
    });
    res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});

express.get("/auth/discord/callback", async (req, res) => {
    const expectedState = req.cookies && req.cookies.flipped_oauth_state;
    res.clearCookie("flipped_oauth_state", COOKIE_OPTIONS);
    if (!req.query.code || !req.query.state || !expectedState || !safeEqual(req.query.state, expectedState)) {
        return res.status(400).send("Discord login failed: invalid or expired OAuth state. Please try again.");
    }
    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !SESSION_SECRET) {
        return res.status(503).send("Discord login is not configured on the server yet.");
    }
    try {
        const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: "authorization_code",
                code: String(req.query.code),
                redirect_uri: DISCORD_CALLBACK_URL
            })
        });
        const tokenData = await tokenResponse.json();
        if (!tokenResponse.ok || !tokenData.access_token) {
            console.error("Discord token exchange failed:", tokenData.error || tokenResponse.status);
            return res.status(502).send("Discord login could not be completed. Please try again.");
        }
        const userResponse = await fetch("https://discord.com/api/users/@me", {
            headers: { Authorization: "Bearer " + tokenData.access_token }
        });
        const discordUser = await userResponse.json();
        if (!userResponse.ok || !discordUser.id) {
            return res.status(502).send("Could not retrieve your Discord profile. Please try again.");
        }
        const user = {
            id: discordUser.id,
            username: discordUser.username,
            global_name: discordUser.global_name || discordUser.username,
            avatar: discordUser.avatar
                ? "https://cdn.discordapp.com/avatars/" + discordUser.id + "/" + discordUser.avatar + ".png"
                : null
        };
        const payload = Buffer.from(JSON.stringify({
            user,
            exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS
        })).toString("base64url");
        res.cookie("flipped_session", payload + "." + sign(payload), {
            ...COOKIE_OPTIONS,
            maxAge: SESSION_MAX_AGE_SECONDS * 1000
        });
        return res.redirect(FRONTEND_URL + "/?discord_login=success");
    } catch (error) {
        console.error("Discord OAuth callback error:", error.message);
        return res.status(502).send("Discord login failed unexpectedly. Please try again.");
    }
});

express.get("/auth/me", (req, res) => {
    const user = readSession(req);
    if (!user) return res.status(401).json({ authenticated: false });
    res.set("Cache-Control", "no-store");
    res.json({ authenticated: true, user });
});

express.post("/auth/logout", (req, res) => {
    res.clearCookie("flipped_session", COOKIE_OPTIONS);
    res.status(200).json({ authenticated: false });
});

express.use(require("./structure/party.js"));
express.use(require("./structure/discovery.js"));
express.use(require("./structure/privacy.js"));
express.use(require("./structure/timeline.js"));
express.use(require("./structure/user.js"));
express.use(require("./structure/contentpages.js"));
express.use(require("./structure/friends.js"));
express.use(require("./structure/main.js"));
express.use(require("./structure/storefront.js"));
express.use(require("./structure/version.js"));
express.use(require("./structure/lightswitch.js"));
express.use(require("./structure/affiliate.js"));
express.use(require("./structure/matchmaking.js"));
express.use(require("./structure/cloudstorage.js"));
express.use(require("./structure/mcp.js"));

const port = process.env.PORT || 3551;
express.listen(port, () => {
    console.log("LawinServer started listening on port", port);
    require("./structure/xmpp.js");
}).on("error", (err) => {
    if (err.code == "EADDRINUSE") console.log(`\x1b[31mERROR\x1b[0m: Port ${port} is already in use!`);
    else throw err;
    process.exit(0);
});

try {
    if (!fs.existsSync(path.join(process.env.LOCALAPPDATA, "LawinServer"))) fs.mkdirSync(path.join(process.env.LOCALAPPDATA, "LawinServer"));
} catch (err) {
    if (!fs.existsSync(path.join(__dirname, "ClientSettings"))) fs.mkdirSync(path.join(__dirname, "ClientSettings"));
}

express.use((req, res) => {
    const XEpicErrorName = "errors.com.lawinserver.common.not_found";
    const XEpicErrorCode = 1004;
    res.set({ "X-Epic-Error-Name": XEpicErrorName, "X-Epic-Error-Code": XEpicErrorCode });
    res.status(404).json({
        errorCode: XEpicErrorName,
        errorMessage: "Sorry the resource you were trying to find could not be found",
        numericErrorCode: XEpicErrorCode,
        originatingService: "any",
        intent: "prod"
    });
});
