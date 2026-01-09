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
// IMPORTANTÍSIMO:
// 1) Webhooks usan RAW body (para HMAC)
// 2) Todo lo demás usa JSON normal
// =====================
app.use("/webhooks", express.raw({ type: "application/json" }));
app.use(express.json());

// =====================
// Helpers: logs simples
// =====================
function log(...args) {
  console.log(new Date().toISOString(), ...args);
}
function warn(...args) {
  console.warn(new Date().toISOString(), ...args);
}
function err(...args) {
  console.error(new Date().toISOString(), ...args);
}

// =====================
// 1) Seguridad Shopify HMAC
// =====================
function verifyShopifyHmac(rawBodyBuffer, hmacHeader) {
  if (!SHOPIFY_WEBHOOK_SECRET) return false;
  if (!hmacHeader) return false;

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
  return pcsTokenCache.token;
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

async function getPcServiceProductIdFromVariant(variantIdNumeric) {
  const gid = `gid://shopify/ProductVariant/${variantIdNumeric}`;
  const q = `
    query GetVariantPcId($id: ID!) {
      node(id: $id) {
        ... on ProductVariant {
          metafield(namespace: "supplier", key: "pcservice_product_id") { value }
        }
      }
    }
  `;
  const data = await shopifyGraphQL(q, { id: gid });
  const mf = data?.node?.metafield?.value || null;
  if (!mf) return null;

  const cleaned = String(mf).trim();
  if (!/^\d+$/.test(cleaned)) return null;
  return parseInt(cleaned, 10);
}

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
  try {
    const hmac = req.get("X-Shopify-Hmac-Sha256");
    if (!verifyShopifyHmac(req.body, hmac)) {
      return res.status(401).send("Invalid HMAC");
    }

    const order = JSON.parse(req.body.toString("utf8"));

    if (!["paid", "partially_paid"].includes(order.financial_status)) {
      return res.status(200).send("Not paid");
    }

    const orderId = order.id;
    const orderNumber = order.order_number;

    const dedupeKey = `orders_paid:${orderId}`;
    if (dedupeSeen(dedupeKey)) {
      log(`[DEDUP] Orden #${orderNumber} ya procesada`);
      return res.status(200).send("OK");
    }

    const pcItems = (order.line_items || []).filter(
      (i) => i && i.vendor === "PC Service" && i.variant_id && i.quantity
    );

    if (pcItems.length === 0) {
      log(`Orden #${orderNumber} sin items de PC Service → ignorada`);
      return res.status(200).send("No PC Service items");
    }

    const cust = order.customer || {};
    const ship = order.shipping_address || {};
    const comment = [
      `Cliente: ${cust.first_name || ""} ${cust.last_name || ""}`.trim(),
      `Tel: ${ship.phone || order.phone || ""}`.trim(),
      `Dir: ${ship.address1 || ""} ${ship.address2 || ""}, ${ship.city || ""}, ${ship.province || ""}`.trim(),
      `CP: ${ship.zip || ""}`.trim(),
    ]
      .filter(Boolean)
      .join(" | ");

    const email = order.email || cust.email || "sin@email.com";
    const shippingMode = "envia";

    const items = [];
    for (const li of pcItems) {
      const pcsProductId = await getPcServiceProductIdFromVariant(li.variant_id);

      if (!pcsProductId) {
        const sku = (li.sku || "").trim();
        if (/^\d+$/.test(sku)) {
          items.push({ productId: parseInt(sku, 10), quantity: li.quantity });
          warn(`[WARN] Variant ${li.variant_id} sin metafield pcservice_product_id; usando SKU numérico como fallback`);
          continue;
        }
        warn(`[SKIP] Item sin pcservice_product_id. variant_id=${li.variant_id}, sku=${li.sku}`);
        continue;
      }

      items.push({ productId: pcsProductId, quantity: li.quantity });
    }

    if (items.length === 0) {
      warn(`Orden #${orderNumber}: no hay items válidos para PC Service (faltan metafields)`);
      return res.status(200).send("No valid items");
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
    err("Webhook error:", e?.message || e);
    return res.status(500).send("Error");
  }
});

// Healthcheck
app.get("/health", (_, res) => res.status(200).send("ok"));

app.listen(PORT, () => log(`Webhook vivo en puerto ${PORT}`));
