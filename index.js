/**
 * pcservice-webhook (Shopify orders/paid -> PCService express_checkout)
 *
 * CAMBIOS CLAVE (arreglos):
 * 1) Logs de entrada SIEMPRE (para ver si llega Shopify y con qué headers)
 * 2) Validación HMAC con rawBody (ya la tenías) + log en caso de mismatch
 * 3) NO usar vendor (vos lo usás para marca). En su lugar:
 *    - Identificar ítems PCService por TAG del producto: "proveedor_pcservice"
 *    - Para eso consultamos GraphQL por variant -> product.tags + metafield pcs id + sku
 * 4) Resolver productId PCS con prioridad:
 *    - supplier.pcservice_product_id (metafield en variant)
 *    - fallback: SKU numérico del variant (si aplica)
 *    - si no hay forma, skip con warn (mejor que mandar mal)
 * 5) Cache de variant lookups (para no hacer 1 llamada GraphQL por ítem siempre)
 * 6) Dedupe en memoria (igual que tenías)
 * 7) Healthcheck /health
 */

const express = require("express");
const fetch = require("node-fetch");
const crypto = require("crypto");

const app = express();

// =====================
// ENV (Render variables)
// =====================
const SHOPIFY_STORE = process.env.SHOPIFY_STORE;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;

const PCS_BASE_URL = process.env.PCS_BASE_URL || "https://www.pcservice.com.uy/rest";
const PCS_USER = process.env.PCS_USER;
const PCS_PASS = process.env.PCS_PASS;

const PORT = process.env.PORT || 3000;

// =====================
// Shopify Webhooks: rawBody for HMAC
// =====================
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf; // Buffer con el body original
    },
  })
);

// =====================
// Helpers: logs simples
// =====================
function iso() {
  return new Date().toISOString();
}
function log(...args) {
  console.log(iso(), ...args);
}
function warn(...args) {
  console.warn(iso(), ...args);
}
function err(...args) {
  console.error(iso(), ...args);
}

// Log de cada request (útil para debug en Render)
app.use((req, res, next) => {
  // NO logueamos body entero para no exponer datos, solo tamaños y headers clave
  const topic = req.get("X-Shopify-Topic") || "";
  const shop = req.get("X-Shopify-Shop-Domain") || "";
  const hmacPresent = !!req.get("X-Shopify-Hmac-Sha256");

  log(`[REQ] ${req.method} ${req.path} topic=${topic || "-"} shop=${shop || "-"} hmac=${hmacPresent ? "present" : "missing"} raw=${req.rawBody?.length || 0}B`);
  next();
});

// =====================
// 1) Seguridad Shopify HMAC
// =====================
function verifyShopifyHmac(rawBodyBuffer, hmacHeader) {
  if (!SHOPIFY_WEBHOOK_SECRET) return false;
  if (!hmacHeader) return false;
  if (!rawBodyBuffer || !(rawBodyBuffer instanceof Buffer)) return false;

  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBodyBuffer)
    .digest("base64");

  const a = Buffer.from(digest);
  const b = Buffer.from(hmacHeader);

  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// =====================
// 2) Dedupe (evitar duplicados)
// =====================
const processed = new Map();
const DEDUPE_TTL_MS = 6 * 60 * 60 * 1000;

function dedupeSeen(key) {
  const now = Date.now();
  for (const [k, t] of processed.entries()) {
    if (now - t > DEDUPE_TTL_MS) processed.delete(k);
  }
  if (processed.has(key)) return true;
  processed.set(key, now);
  return false;
}

// =====================
// 3) PC Service token cache
// =====================
let pcsTokenCache = { token: null, expiresAt: 0 };

async function getPcServiceToken() {
  const now = Date.now();
  if (pcsTokenCache.token && pcsTokenCache.expiresAt - now > 2 * 60 * 1000) {
    return pcsTokenCache.token;
  }

  if (!PCS_USER || !PCS_PASS) {
    throw new Error("Faltan PCS_USER / PCS_PASS en variables de entorno");
  }

  const r = await fetch(`${PCS_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: PCS_USER, password: PCS_PASS }),
  });

  const txt = await r.text();
  if (!r.ok) throw new Error(`PC Service login failed (${r.status}): ${txt}`);

  const j = JSON.parse(txt);
  if (!j.token) throw new Error("PC Service login: respuesta sin token");

  pcsTokenCache = { token: j.token, expiresAt: now + 14 * 60 * 1000 };
  return j.token;
}

// =====================
// 4) Shopify GraphQL helper
// =====================
async function shopifyGraphQL(query, variables = {}) {
  if (!SHOPIFY_STORE || !SHOPIFY_ADMIN_TOKEN) {
    throw new Error("Faltan SHOPIFY_STORE / SHOPIFY_ADMIN_TOKEN");
  }

  const url = `https://${SHOPIFY_STORE}/admin/api/2025-07/graphql.json`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });

  const txt = await r.text();
  let j;
  try {
    j = JSON.parse(txt);
  } catch {
    throw new Error(`Shopify GraphQL invalid JSON: ${txt}`);
  }

  if (!r.ok) throw new Error(`Shopify GraphQL HTTP ${r.status}: ${txt}`);
  if (j.errors && j.errors.length) throw new Error(`Shopify GraphQL errors: ${JSON.stringify(j.errors)}`);

  return j.data;
}

// =====================
// 4.1) Variant lookup con TAG proveedor_pcservice + pcs id
// =====================
const VARIANT_CACHE = new Map();
const VARIANT_CACHE_TTL_MS = 10 * 60 * 1000; // 10 min

function cacheGetVariant(variantId) {
  const hit = VARIANT_CACHE.get(variantId);
  if (!hit) return null;
  if (Date.now() - hit.t > VARIANT_CACHE_TTL_MS) {
    VARIANT_CACHE.delete(variantId);
    return null;
  }
  return hit.v;
}

function cacheSetVariant(variantId, value) {
  VARIANT_CACHE.set(variantId, { t: Date.now(), v: value });
}

async function getVariantPcserviceData(variantIdNumeric) {
  const cached = cacheGetVariant(variantIdNumeric);
  if (cached) return cached;

  const gid = `gid://shopify/ProductVariant/${variantIdNumeric}`;
  const q = `
    query VariantPcservice($id: ID!) {
      node(id: $id) {
        ... on ProductVariant {
          sku
          metafield(namespace: "supplier", key: "pcservice_product_id") { value }
          product { tags }
        }
      }
    }
  `;

  const data = await shopifyGraphQL(q, { id: gid });

  const tags = data?.node?.product?.tags || [];
  const isPc = tags.includes("proveedor_pcservice");

  const mf = data?.node?.metafield?.value || null;
  const cleaned = mf ? String(mf).trim() : "";
  const pcsId = /^\d+$/.test(cleaned) ? parseInt(cleaned, 10) : null;

  const sku = data?.node?.sku ? String(data.node.sku).trim() : "";
  const skuNum = /^\d+$/.test(sku) ? parseInt(sku, 10) : null;

  const value = { isPc, pcsId, sku, skuNum, tags };
  cacheSetVariant(variantIdNumeric, value);
  return value;
}

// =====================
// 4.2) Guardar pcservice_orderid en la Orden (metafield)
// =====================
async function setOrderPcServiceOrderId(orderIdNumeric, pcsOrderId) {
  const orderGid = `gid://shopify/Order/${orderIdNumeric}`;
  const m = `
    mutation SetOrderMetafield($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        userErrors { field message }
      }
    }
  `;
  const variables = {
    metafields: [
      {
        ownerId: orderGid,
        namespace: "supplier",
        key: "pcservice_orderid",
        type: "single_line_text_field",
        value: String(pcsOrderId),
      },
    ],
  };

  const data = await shopifyGraphQL(m, variables);
  const errs = data?.metafieldsSet?.userErrors || [];
  if (errs.length) warn("No pude guardar metafield en order:", JSON.stringify(errs));
}

// =====================
// 5) Crear orden en PC Service
// =====================
async function createPcServiceOrder({ orderNumber, email, comment, items, shipping }) {
  const token = await getPcServiceToken();

  const payload = {
    description: `Orden Shopify #${orderNumber}`,
    email: email || "sin@email.com",
    comment: comment || "",
    items,
    extraData: { shipping: shipping || "envia" },
  };

  const r = await fetch(`${PCS_BASE_URL}/orders/express_checkout`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const txt = await r.text();
  if (!r.ok) throw new Error(`PC Service express_checkout failed (${r.status}): ${txt}`);

  const j = JSON.parse(txt);
  if (!j.orderid) throw new Error(`PC Service: respuesta sin orderid: ${txt}`);
  return j.orderid;
}

// =====================
// Webhook: orders/paid
// =====================
app.post("/webhooks/orders_paid", async (req, res) => {
  const topic = req.get("X-Shopify-Topic") || "";
  const shop = req.get("X-Shopify-Shop-Domain") || "";
  const hmac = req.get("X-Shopify-Hmac-Sha256");

  try {
    // Validar HMAC con rawBody (Buffer)
    if (!verifyShopifyHmac(req.rawBody, hmac)) {
      warn(`[HMAC] Invalid HMAC topic=${topic || "-"} shop=${shop || "-"} raw=${req.rawBody?.length || 0}B`);
      return res.status(401).send("Invalid HMAC");
    }

    const order = req.body || {};
    const financial = order.financial_status;

    log(`[WEBHOOK] orders_paid received id=${order.id || "-"} order_number=${order.order_number || "-"} financial_status=${financial || "-"}`);

    // Solo pagadas
    if (!["paid", "partially_paid"].includes(financial)) {
      log(`[SKIP] Not paid financial_status=${financial}`);
      return res.status(200).send("Not paid");
    }

    const orderId = order.id;
    const orderNumber = order.order_number;

    const dedupeKey = `orders_paid:${orderId}`;
    if (dedupeSeen(dedupeKey)) {
      log(`[DEDUP] Orden #${orderNumber} ya procesada`);
      return res.status(200).send("OK");
    }

    // Construimos comentario/cliente
    const cust = order.customer || {};
    const ship = order.shipping_address || {};
    const comment = [
      `Cliente: ${cust.first_name || ""} ${cust.last_name || ""}`.trim(),
      `Tel: ${ship.phone || order.phone || ""}`.trim(),
      `Dir: ${ship.address1 || ""} ${ship.address2 || ""}, ${ship.city || ""}, ${ship.province || ""}`.trim(),
      `CP: ${ship.zip || ""}`.trim(),
    ]
      .map((s) => s.trim())
      .filter(Boolean)
      .join(" | ");

    const email = order.email || cust.email || "sin@email.com";
    const shippingMode = "envia"; // o podés mapear según tu lógica

    // Armar items PCService por TAG proveedor_pcservice
    const items = [];
    const vendorsSeen = new Set();

    for (const li of order.line_items || []) {
      if (!li?.variant_id || !li?.quantity) continue;
      if (li.vendor) vendorsSeen.add(li.vendor);

      const info = await getVariantPcserviceData(li.variant_id);

      // Solo productos PCService por tag (fuente de verdad)
      if (!info.isPc) continue;

      // Resolver productId
      const productId = info.pcsId || info.skuNum;

      if (!productId) {
        warn(
          `[SKIP] PCService item sin supplier.pcservice_product_id y SKU no numérico. variant_id=${li.variant_id} sku=${info.sku}`
        );
        continue;
      }

      items.push({ productId, quantity: li.quantity });
    }

    log(`[DEBUG] Orden #${orderNumber} vendors_en_orden=${Array.from(vendorsSeen).join(", ") || "-"}`);
    log(`[DEBUG] Orden #${orderNumber} pcs_items_count=${items.length}`);

    if (items.length === 0) {
      log(`Orden #${orderNumber} sin items PCService válidos (tag proveedor_pcservice) → ignorada`);
      return res.status(200).send("No PC Service items");
    }

    const pcsOrderId = await createPcServiceOrder({
      orderNumber,
      email,
      comment,
      items,
      shipping: shippingMode,
    });

    log(`OK → Orden #${orderNumber} enviada a PC Service. pcservice_orderid=${pcsOrderId}`);

    await setOrderPcServiceOrderId(orderId, pcsOrderId);

    return res.status(200).send("OK");
  } catch (e) {
    err(`[ERR] Webhook orders_paid topic=${topic || "-"} shop=${shop || "-"}:`, e?.message || e);
    return res.status(500).send("Error");
  }
});

// Healthcheck
app.get("/health", (_, res) => res.status(200).send("ok"));

app.listen(PORT, () => log(`Webhook vivo en puerto ${PORT}`));
