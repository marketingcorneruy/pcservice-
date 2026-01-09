const express = require("express");
const fetch = require("node-fetch");
const crypto = require("crypto");

const app = express();

// Para rutas NO-webhook (health, etc.)
app.use(express.json());

// =====================
// ENV (Render variables)
// =====================
const SHOPIFY_STORE = process.env.SHOPIFY_STORE; // ej: 00wwev-11.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN; // Admin API token
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET; // Webhook secret

const PCS_BASE_URL = process.env.PCS_BASE_URL || "https://www.pcservice.com.uy/rest";
const PCS_USER = process.env.PCS_USER;
const PCS_PASS = process.env.PCS_PASS;

const PORT = process.env.PORT || 3000;

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
// Nota ELI5: esto guarda en memoria “ya procesé esta orden”.
// Si Render reinicia el servicio, se olvida. Más adelante podemos usar Redis/DB si querés.
const processed = new Map(); // key -> timestamp
const DEDUPE_TTL_MS = 6 * 60 * 60 * 1000; // 6 horas

function dedupeSeen(key) {
  const now = Date.now();
  // Limpieza simple
  for (const [k, t] of processed.entries()) {
    if (now - t > DEDUPE_TTL_MS) processed.delete(k);
  }
  if (processed.has(key)) return true;
  processed.set(key, now);
  return false;
}

// =====================
// 3) PC Service token cache (JWT ~15min)
// =====================
let pcsTokenCache = {
  token: null,
  expiresAt: 0, // epoch ms
};

async function getPcServiceToken() {
  const now = Date.now();
  // Si falta menos de 2 minutos, refrescar
  if (pcsTokenCache.token && (pcsTokenCache.expiresAt - now) > 2 * 60 * 1000) {
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
  if (!r.ok) {
    throw new Error(`PC Service login failed (${r.status}): ${txt}`);
  }

  const j = JSON.parse(txt);
  if (!j.token) throw new Error("PC Service login: respuesta sin token");

  // Token dura ~15 min -> cacheamos 14 min para ir seguros
  pcsTokenCache = {
    token: j.token,
    expiresAt: now + 14 * 60 * 1000,
  };

  return pcsTokenCache.token;
}

// =====================
// 4) Shopify GraphQL helper
// =====================
async function shopifyGraphQL(query, variables = {}) {
  if (!SHOPIFY_STORE || !SHOPIFY_ADMIN_TOKEN) {
    throw new Error("Faltan SHOPIFY_STORE / SHOPIFY_ADMIN_TOKEN en variables de entorno");
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

  if (!r.ok) {
    throw new Error(`Shopify GraphQL HTTP ${r.status}: ${txt}`);
  }

  if (j.errors && j.errors.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(j.errors)}`);
  }

  return j.data;
}

// Leer metafield del variant: supplier.pcservice_product_id
async function getPcServiceProductIdFromVariant(variantIdNumeric) {
  const gid = `gid://shopify/ProductVariant/${variantIdNumeric}`;

  const q = `
    query GetVariantPcId($id: ID!) {
      node(id: $id) {
        ... on ProductVariant {
          id
          metafield(namespace: "supplier", key: "pcservice_product_id") {
            value
          }
        }
      }
    }
  `;

  const data = await shopifyGraphQL(q, { id: gid });
  const mf = data?.node?.metafield?.value || null;

  if (!mf) return null;

  // Aceptamos "55155" y también " 55155 "
  const cleaned = String(mf).trim();
  if (!/^\d+$/.test(cleaned)) return null;
  return parseInt(cleaned, 10);
}

// Guardar el orderid del proveedor como metafield en la Order
async function setOrderPcServiceOrderId(orderIdNumeric, pcsOrderId) {
  const orderGid = `gid://shopify/Order/${orderIdNumeric}`;

  const m = `
    mutation SetOrderMetafield($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        metafields { id }
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
  if (errs.length) {
    warn("No pude guardar metafield en order:", JSON.stringify(errs));
  }
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
    items, // [{productId, quantity}]
    extraData: { shipping: shipping || "envia" },
  };

  const r = await fetch(`${PCS_BASE_URL}/orders/express_checkout`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const txt = await r.text();
  if (!r.ok) {
    throw new Error(`PC Service express_checkout failed (${r.status}): ${txt}`);
  }

  const j = JSON.parse(txt);
  if (!j.orderid) throw new Error(`PC Service: respuesta sin orderid: ${txt}`);

  return j.orderid;
}

// =====================
// Webhook: orders/paid
// =====================
// ELI5: usamos raw body SOLO en webhooks para verificar HMAC bien.
app.post("/webhooks/orders_paid", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const hmac = req.get("X-Shopify-Hmac-Sha256");
    if (!verifyShopifyHmac(req.body, hmac)) {
      return res.status(401).send("Invalid HMAC");
    }

    const order = JSON.parse(req.body.toString("utf8"));

    // Shopify manda "paid" para orders/paid, pero igual chequeamos:
    if (!["paid", "partially_paid"].includes(order.financial_status)) {
      return res.status(200).send("Not paid");
    }

    const orderId = order.id;
    const orderNumber = order.order_number;

    const dedupeKey = `orders_paid:${orderId}`;
    if (dedupeSeen(dedupeKey)) {
      log(`[DEDUP] Orden #${orderNumber} (${orderId}) ya procesada`);
      return res.status(200).send("OK");
    }

    // 1) Filtrar items de PC Service (vendor exacto con espacio)
    const pcItems = (order.line_items || []).filter(
      (i) => i && i.vendor === "PC Service" && i.variant_id && i.quantity
    );

    if (pcItems.length === 0) {
      log(`Orden #${orderNumber} sin items de PC Service → ignorada`);
      return res.status(200).send("No PC Service items");
    }

    // 2) Armar comment (datos del cliente/envío)
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

    // Shipping (simple): default envia
    // Si algún día querés detectar “retiro”, lo hacemos según shipping_lines/title
    const shippingMode = "envia";

    // 3) Convertir items Shopify -> items PC Service (NECESITA productId)
    const items = [];
    for (const li of pcItems) {
      const pcsProductId = await getPcServiceProductIdFromVariant(li.variant_id);

      if (!pcsProductId) {
        // fallback: si SKU es numérico, lo intentamos como productId (por compatibilidad)
        const sku = (li.sku || "").trim();
        if (/^\d+$/.test(sku)) {
          items.push({ productId: parseInt(sku, 10), quantity: li.quantity });
          warn(`[WARN] Variant ${li.variant_id} sin metafield pcservice_product_id; usando SKU numérico como fallback`);
          continue;
        }

        // si no hay forma, lo salteamos (mejor que mandar mal)
        warn(`[SKIP] Item sin pcservice_product_id. Orden #${orderNumber}, variant_id=${li.variant_id}, sku=${li.sku}`);
        continue;
      }

      items.push({ productId: pcsProductId, quantity: li.quantity });
    }

    if (items.length === 0) {
      warn(`Orden #${orderNumber}: no pude construir items válidos para PC Service (faltan metafields)`);
      return res.status(200).send("No valid items");
    }

    // 4) Enviar orden a PC Service
    const pcsOrderId = await createPcServiceOrder({
      orderNumber,
      email,
      comment,
      items,
      shipping: shippingMode,
    });

    log(`OK → Orden #${orderNumber} enviada a PC Service. pcservice_orderid=${pcsOrderId}`);

    // 5) Guardar el orderid del proveedor en Shopify (metafield order)
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
