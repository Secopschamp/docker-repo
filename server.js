const express = require("express");
const crypto = require("crypto");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const path = require("path");
const fetch = require("node-fetch");

dotenv.config();

const app = express();
app.use(cookieParser());
app.use(express.json());

const PORT = 8080;
const ORG_NAME = process.env.GITHUB_ORG;
const TOKEN_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
const REVEAL_TTL_MS = 15 * 60 * 1000;   // 15 minutes after reveal
const isProduction = false;

/* ------------------------ In-memory store ------------------------ */
// session_id -> { token, expiry, revealed }
const sessionTokens = new Map();

/* ------------------------ Utilities ------------------------ */
function base64URLEncode(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

function maskToken(token) {
  return token ? token.slice(0, -8) + "*".repeat(8) : "********";
}

/* ------------------------ Org validation ------------------------ */
async function validateOrgMembership(token) {
  const res = await fetch("https://api.github.com/user/memberships/orgs", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json"
    }
  });

  if (!res.ok) return false;

  const memberships = await res.json();
  return memberships.some(
    m => m.organization.login === ORG_NAME && m.state === "active"
  );
}

/* ------------------------ Root ------------------------ */
app.get("/", async (req, res) => {
  const session = sessionTokens.get(req.cookies.session_id);

  if (session && session.expiry > Date.now()) {
    const stillMember = await validateOrgMembership(session.token);
    if (!stillMember) {
      sessionTokens.delete(req.cookies.session_id);
      return res.status(403).send("Access denied");
    }
    return res.sendFile(path.join(__dirname, "frontend", "index.html"));
  }

  // Start OAuth
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  res.cookie("oauth_state", state, { httpOnly: true, sameSite: "lax", secure: isProduction });
  res.cookie("code_verifier", codeVerifier, { httpOnly: true, sameSite: "lax", secure: isProduction });

  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_CALLBACK_URL,
    state,
    scope: "read:org read:packages write:packages",
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.use(express.static(path.join(__dirname, "frontend")));

/* ------------------------ OAuth callback ------------------------ */
app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  if (state !== req.cookies.oauth_state) {
    return res.status(403).send("Invalid OAuth state");
  }

  res.clearCookie("oauth_state");
  res.clearCookie("code_verifier");

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
      code_verifier: req.cookies.code_verifier
    })
  });

  const { access_token } = await tokenRes.json();
  if (!access_token) return res.status(500).send("Token exchange failed");

  const isMember = await validateOrgMembership(access_token);
  if (!isMember) return res.status(403).send("Not an org member");

  const sessionId = crypto.randomBytes(16).toString("hex");

  sessionTokens.set(sessionId, {
    token: access_token,
    expiry: Date.now() + TOKEN_TTL_MS,
    revealed: false
  });

  res.cookie("session_id", sessionId, { httpOnly: true, sameSite: "lax", secure: isProduction });
  res.redirect("/");
});

/* ------------------------ Token metadata ------------------------ */
app.get("/token-data", async (req, res) => {
  const session = sessionTokens.get(req.cookies.session_id);

  if (!session || session.expiry < Date.now()) {
    return res.status(403).json({ error: "Session expired" });
  }

  const stillMember = await validateOrgMembership(session.token);
  if (!stillMember) {
    sessionTokens.delete(req.cookies.session_id);
    return res.status(403).json({ error: "Access denied" });
  }

  res.json({
    masked_token: maskToken(session.token),
    expiry: session.expiry,
    revealed: session.revealed
  });
});

/* ------------------------ One-time reveal ------------------------ */
app.post("/token/reveal", async (req, res) => {
  const session = sessionTokens.get(req.cookies.session_id);

  if (!session || session.expiry < Date.now()) {
    return res.status(403).json({ error: "Session expired" });
  }

  const stillMember = await validateOrgMembership(session.token);
  if (!stillMember) {
    sessionTokens.delete(req.cookies.session_id);
    return res.status(403).json({ error: "Access denied" });
  }

  if (session.revealed) {
    return res.status(403).json({ error: "Token already revealed" });
  }

  session.revealed = true;
  session.expiry = Math.min(session.expiry, Date.now() + REVEAL_TTL_MS);

  res.json({ access_token: session.token });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
