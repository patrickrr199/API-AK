// ============================================================================
//  ⚠️  LAB-ONLY INTENTIONALLY VULNERABLE API  ⚠️
// ----------------------------------------------------------------------------
//  This Supabase Edge Function contains DELIBERATE security vulnerabilities.
//  Its only purpose is to be scanned by a DAST tool (Aikido) in an isolated
//  test project. DO NOT deploy to a project holding real data, DO NOT expose
//  long-term, and DELETE the Supabase project when you finish testing.
//
//  Each endpoint is tagged with the OWASP API Top 10 issue it demonstrates.
// ============================================================================

import { Client } from "https://deno.land/x/postgres@v0.19.3/mod.ts";

const DB_URL = Deno.env.get("SUPABASE_DB_URL")!;

// --- VULN: overly permissive CORS (reflects any origin, allows credentials) --
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Allow-Methods": "*",
  "Access-Control-Allow-Credentials": "true",
};

// --- VULN: hardcoded weak JWT secret, checked in source control -------------
const JWT_SECRET = "supersecret123";

function json(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...extra },
  });
}

async function db() {
  const client = new Client(DB_URL);
  await client.connect();
  return client;
}

// --- VULN: home-made "JWT" with no signature verification -------------------
function makeToken(userId: number, role: string) {
  const payload = btoa(JSON.stringify({ userId, role, s: JWT_SECRET }));
  return `lab.${payload}`;
}
function parseToken(auth: string | null) {
  if (!auth) return null;
  try {
    const raw = auth.replace(/^Bearer\s+/i, "").replace(/^lab\./, "");
    return JSON.parse(atob(raw)); // trusts client-supplied claims blindly
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  const url = new URL(req.url);
  // strip the "/api" function prefix so routes are clean
  const path = url.pathname.replace(/^.*\/api/, "") || "/";
  const method = req.method;

  try {
    // ---------------------------------------------------------------- health
    if (path === "/" || path === "/health") {
      return json({ status: "ok", warning: "intentionally vulnerable lab API" });
    }

    // -------------------------------------------------- POST /login  (SQLi + weak auth)
    if (path === "/login" && method === "POST") {
      const { username, password } = await req.json();
      const c = await db();
      // VULN: SQL injection via string concatenation (API8/A03)
      const q = `SELECT id, username, role FROM users
                 WHERE username = $1 AND password = $2`;
      const params = [username, password];
      const r = await c.queryObject(q, params);
      await c.end();
      if (r.rows.length === 0) return json({ error: "invalid credentials" }, 401);
      const u = r.rows[0] as { id: number; username: string; role: string };
      return json({ token: makeToken(u.id, u.role), user: u });
    }

    // -------------------------------------------------- GET /users/:id  (BOLA/IDOR)
    const userMatch = path.match(/^\/users\/(\w+)$/);
    if (userMatch && method === "GET") {
      const id = userMatch[1];
      const c = await db();
      // VULN: no authorization / ownership check (API1 BOLA) + SQLi + returns
      //       password hashes & tokens (API3 excessive data exposure)
      const r = await c.queryObject(
        `SELECT * FROM users WHERE id = ${id}`,
      );
      await c.end();
      return json({ user: r.rows[0] ?? null });
    }

    // -------------------------------------------------- GET /users  (data exposure)
    if (path === "/users" && method === "GET") {
      const c = await db();
      // VULN: no auth required, dumps every column including secrets
      const r = await c.queryObject(`SELECT * FROM users`);
      await c.end();
      return json({ users: r.rows });
    }

    // -------------------------------------------------- PUT /users/:id  (mass assignment)
    if (userMatch && method === "PUT") {
      const id = userMatch[1];
      const body = await req.json();
      const c = await db();
      // VULN: mass assignment — client can set ANY column incl. role=admin (API6)
      const entries = Object.entries(body);
      for (const [k] of entries) {
        if (!/^[a-zA-Z0-9_]+$/.test(k)) throw new Error('Invalid input');
      }
      const sets = entries
        .map(([k], i) => `${k} = $${i + 1}`)
        .join(", ");
      const values = entries.map(([, v]) => v);
      const params = [...values, id];
      await c.queryObject(`UPDATE users SET ${sets} WHERE id = $${values.length + 1}`, params);
      const params2 = [id];
      const r = await c.queryObject(`SELECT * FROM users WHERE id = $1`, params2);
      await c.end();
      return json({ user: r.rows[0] ?? null });
    }

    // -------------------------------------------------- GET /admin/config  (broken auth)
    if (path === "/admin/config" && method === "GET") {
      const claims = parseToken(req.headers.get("Authorization"));
      // VULN: role taken from unverified client token (API5 broken function auth)
      if (!claims || claims.role !== "admin") return json({ error: "forbidden" }, 403);
      return json({
        db_url: DB_URL,
        jwt_secret: JWT_SECRET,
        note: "secrets leaked to anyone who forges an admin token",
      });
    }

    // -------------------------------------------------- GET /fetch?url=  (SSRF)
    if (path === "/fetch" && method === "GET") {
      const target = url.searchParams.get("url") ?? "";
      // VULN: server-side request forgery — fetches arbitrary URLs incl. metadata
      const upstream = await fetch(target);
      const text = await upstream.text();
      return json({ url: target, body: text.slice(0, 2000) });
    }

    // -------------------------------------------------- GET /search?q=  (reflected XSS)
    if (path === "/search" && method === "GET") {
      const q = url.searchParams.get("q") ?? "";
      // VULN: reflected XSS, user input echoed into HTML unescaped (A03)
      const html = `<html><body><h1>Results for: ${q}</h1></body></html>`;
      return new Response(html, {
        headers: { "Content-Type": "text/html", ...CORS },
      });
    }

    // -------------------------------------------------- POST /products  (no rate limit / no auth)
    if (path === "/products" && method === "POST") {
      const { name, price } = await req.json();
      const c = await db();
      const params = [name, price];
      const r = await c.queryObject(
        `INSERT INTO products (name, price) VALUES ($1, $2) RETURNING *`,
        params,
      );
      await c.end();
      return json({ product: r.rows[0] }, 201);
    }

    if (path === "/products" && method === "GET") {
      const c = await db();
      const r = await c.queryObject(`SELECT * FROM products`);
      await c.end();
      return json({ products: r.rows });
    }

    return json({ error: "not found", path }, 404);
  } catch (e) {
    // VULN: verbose error disclosure (leaks SQL / stack details) (API8)
    return json({ error: String(e), stack: (e as Error).stack }, 500);
  }
});
