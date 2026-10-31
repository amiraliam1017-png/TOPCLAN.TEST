import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";

export const config = { path: "/api/*" };

const store = (n) => getStore({ name: n, consistency: "strong" });
const json = (o, s = 200, h = {}) =>
  new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...h } });
const newId = () => Date.now().toString(36) + randomBytes(4).toString("hex");
const clip = (v, n) => String(v == null ? "" : v).trim().slice(0, n);

const PASS = () => process.env.ADMIN_PASSWORD || "";
const sign = (p) => createHmac("sha256", "top-v1:" + PASS()).update(p).digest("hex");
const makeToken = () => { const exp = Date.now() + 12 * 3600 * 1000; return exp + "." + sign(String(exp)); };
function validToken(t) {
  if (!PASS() || !t) return false;
  const [exp, sig] = String(t).split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && timingSafeEqual(a, b);
}
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };

// محدودیت تعداد درخواست بر اساس IP: max بار در windowSec ثانیه
async function limited(kind, ip, max, windowSec) {
  const s = store("limits"), key = kind + ":" + String(ip).replace(/[^\w.:-]/g, "_");
  const now = Date.now();
  let r = (await s.get(key, { type: "json" })) || { n: 0, t: now };
  if (now - r.t > windowSec * 1000) r = { n: 0, t: now };
  r.n++;
  await s.setJSON(key, r);
  return r.n > max;
}

async function listAll(name, limit = 300) {
  const s = store(name);
  const { blobs } = await s.list();
  const items = (await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })))).filter(Boolean);
  return items.sort((a, b) => b.ts - a.ts).slice(0, limit);
}

export default async (req, context) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const method = req.method;
  const ip = context.ip || req.headers.get("x-nf-client-connection-ip") || "unknown";
  let body = {};
  if (method === "POST") { try { body = await req.json(); } catch { body = {}; } }

  if (path === "health") return json({ ok: true });

  // ---------- عمومی ----------
  if (path === "comments" && method === "GET") return json({ comments: await listAll("comments") });
  if (path === "comments" && method === "POST") {
    const text = clip(body.text, 500);
    if (!text) return json({ ok: false, error: "متن نظر خالی است" }, 400);
    if (await limited("c", ip, 5, 600)) return json({ ok: false, error: "تعداد نظرها زیاد است؛ کمی بعد دوباره تلاش کنید" }, 429);
    const id = newId();
    await store("comments").setJSON(id, { id, name: clip(body.name, 40), text, ts: Date.now() });
    return json({ ok: true });
  }

  if (path === "photos" && method === "GET") {
    const list = await listAll("photos", 120);
    return json({ photos: list.map((p) => ({ ...p, url: "/api/photo/" + p.id })) });
  }
  if (path === "photos" && method === "POST") {
    const data = String(body.data || "");
    if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(data) || data.length > 2_500_000)
      return json({ ok: false, error: "عکس نامعتبر یا بیش از حد بزرگ است" }, 400);
    if (await limited("p", ip, 5, 600)) return json({ ok: false, error: "تعداد آپلودها زیاد است؛ کمی بعد دوباره تلاش کنید" }, 429);
    const id = newId();
    await store("photo-data").set(id, data);
    await store("photos").setJSON(id, { id, caption: clip(body.caption, 120), ts: Date.now() });
    return json({ ok: true });
  }
  if (path.startsWith("photo/") && method === "GET") {
    const data = await store("photo-data").get(path.slice(6).replace(/[^\w-]/g, ""));
    if (!data) return new Response("not found", { status: 404 });
    const bin = Buffer.from(data.split(",")[1], "base64");
    return new Response(bin, { headers: { "Content-Type": "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable" } });
  }

  if (path === "news" && method === "GET") return json({ news: await listAll("news", 100) });

  // ---------- ورود ----------
  if (path === "admin/login" && method === "POST") {
    if (!PASS()) return json({ ok: false, error: "رمز مدیریت روی سرور تنظیم نشده است" }, 500);
    if (await limited("login", ip, 6, 900)) return json({ ok: false, error: "تلاش بیش از حد؛ ۱۵ دقیقه بعد امتحان کنید" }, 429);
    if (!safeEq(String(body.password || ""), PASS())) return json({ ok: false, error: "رمز اشتباه است" }, 401);
    return json({ ok: true, token: makeToken() });
  }

  // ---------- فقط مدیر ----------
  if (path.startsWith("admin/")) {
    const auth = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "") || url.searchParams.get("token") || body.token;
    if (!validToken(auth)) return json({ ok: false, error: "غیرمجاز" }, 401);

    if (path === "admin/logout") return json({ ok: true });
    if (path === "admin/stats") {
      const n = async (x) => (await store(x).list()).blobs.length;
      return json({ comments: await n("comments"), photos: await n("photos"), news: await n("news") });
    }
    if (path === "admin/add-news" && method === "POST") {
      const title = clip(body.title, 80), text = clip(body.text, 600);
      if (!title || !text) return json({ ok: false, error: "عنوان و متن لازم است" }, 400);
      const id = newId();
      await store("news").setJSON(id, { id, title, text, tag: clip(body.tag, 20), ts: Date.now() });
      return json({ ok: true });
    }
    const del = { "admin/delete-comment": ["comments"], "admin/delete-news": ["news"], "admin/delete-photo": ["photos", "photo-data"] }[path];
    if (del && method === "POST") {
      const id = String(body.id || "").replace(/[^\w-]/g, "");
      if (!id) return json({ ok: false, error: "شناسه نامعتبر" }, 400);
      for (const n of del) await store(n).delete(id);
      return json({ ok: true });
    }
  }

  return json({ ok: false, error: "یافت نشد" }, 404);
};
