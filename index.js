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
 * 8) Detección de shipping mode desde shipping_lines de Shopify:
 *    - "Retiro en PC Service" / "retiro" / "pickup" / local_pickup → "retira"
 *    - Todo lo demás (envío express, envío estándar)                → "envia"
 * 9) Metafield supplier.pcs_shipping_mode en la orden (trazabilidad)
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
// 4.3) Guardar shipping mode en metafield de la orden
// =====================
async function setOrderShippingMode(orderIdNumeric, shippingMode) {
  const orderGid = `gid://shopify/Order/${orderIdNumeric}`;
  const m = `
    mutation SetShippingMeta($metafields: [MetafieldsSetInput!]!) {
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
        key: "pcs_shipping_mode",
        type: "single_line_text_field",
        value: shippingMode,
      },
    ],
  };

  const data = await shopifyGraphQL(m, variables);
  const errs = data?.metafieldsSet?.userErrors || [];
  if (errs.length) warn("No pude guardar pcs_shipping_mode metafield:", JSON.stringify(errs));
}

// =====================
// 5) Crear orden en PC Service
// =====================
async function createPcServiceOrder({ orderNumber, email, comment, items, shipping }) {
  const token = await getPcServiceToken();

  const payload = {
    description: `Orden Dropshipping #${orderNumber}`,
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
// 6) Detectar shipping mode desde Shopify order
// =====================
/**
 * Lee shipping_lines + note_attributes de la orden de Shopify y determina
 * el shipping mode hacia PCS:
 *   - "envia":  PCS despacha vía DAC al destino indicado en el comment (DEFAULT)
 *   - "retira": Corner pasa a buscar el pedido al local de PCS (excepción)
 *
 * IMPORTANTE — setup actual del checkout de Shopify (Abr 2026):
 *   La única opción de envío del cliente es "Envío por DAC". Pickup fue removido
 *   porque PCS no ofrece retiro a consumidor final, solo retiro Corner.
 *   Por eso el default es "envia" → PCS despacha vía DAC al destino del cliente,
 *   que se le pasa a PCS en el campo `comment` (CI, Tel, Dir, CP).
 *
 * Prioridad:
 *  1. note_attribute _pcs_shipping override (manual, para casos de retiro Corner)
 *  2. shipping_line title contiene "retiro" / código "local_pickup" → "retira"
 *  3. Default → "envia" (el caso normal: cliente eligió Envío por DAC)
 */
function detectShippingMode(order) {
  // 1. Override manual via note_attribute (casos especiales)
  const noteAttrs = order.note_attributes || [];
  for (const attr of noteAttrs) {
    if (attr.name === "_pcs_shipping" || attr.name === "pcs_shipping") {
      const val = (attr.value || "").toLowerCase().trim();
      if (val === "retira" || val === "pickup") return "retira";
      if (val === "envia" || val === "dac" || val === "express") return "envia";
    }
  }

  // 2. Shipping rate de retiro Corner (en caso de re-habilitarse algún día)
  const shippingLines = order.shipping_lines || [];
  for (const sl of shippingLines) {
    const title = (sl.title || "").toLowerCase();
    const code  = (sl.code  || "").toLowerCase();

    if (
      title.includes("retiro corner") ||
      title.includes("retiro en pc service") ||
      code === "local_pickup" ||
      code.includes("pcs_retira")
    ) {
      return "retira";
    }
  }

  // 3. Default: PCS despacha al cliente vía DAC (caso normal post-Abr 2026)
  return "envia";
}

/**
 * Extraer CI / RUT del cliente desde la orden de Shopify.
 *
 * SETUP CORNER (Abr 2026):
 *   El checkout de Shopify usa el campo "Company" (renombrado "CI / RUT" via
 *   Translate & Adapt: Contact > Company Label = "CI / RUT"). El cliente escribe
 *   ahi su cedula o RUT, y Shopify lo guarda en `shipping_address.company`
 *   (y/o `billing_address.company` si el billing es distinto).
 *
 * Prioridad de lookup:
 *   1. shipping_address.company   <- caso normal post-Abr 2026
 *   2. billing_address.company    <- por si el billing tiene CI distinto
 *   3. note_attributes            <- fallback para checkouts custom
 *   4. line_items[].properties    <- fallback por si esta como property
 *
 * Aceptamos cualquier valor con al menos 6 digitos cuando se quitan no-digitos
 * (cubre formatos "1.234.567-8", "12345678", "21-602622-001-5000" para RUT).
 */
function extractCustomerCI(order) {
  // 1. shipping_address.company  (caso normal)
  const shipCo = String(order.shipping_address?.company || "").trim();
  if (shipCo && shipCo.replace(/\D/g, "").length >= 6) return shipCo;

  // 2. billing_address.company
  const billCo = String(order.billing_address?.company || "").trim();
  if (billCo && billCo.replace(/\D/g, "").length >= 6) return billCo;

  // 3. note_attributes
  const candidates = ["ci", "cedula", "cédula", "rut", "dni", "documento", "doc", "tax_id"];
  for (const na of order.note_attributes || []) {
    const name = String(na.name || "").toLowerCase().trim();
    if (candidates.includes(name)) {
      const val = String(na.value || "").trim();
      if (val) return val;
    }
  }

  // 4. line_items[].properties
  for (const li of order.line_items || []) {
    for (const p of li.properties || []) {
      const name = String(p.name || "").toLowerCase().trim();
      if (candidates.includes(name)) {
        const val = String(p.value || "").trim();
        if (val) return val;
      }
    }
  }

  return "";
}

/**
 * Construye el `comment` del express_checkout segun el shipping mode.
 *
 * Formato (single-line, separado por " | "):
 *   - Retiro Corner: "Cliente: {nombre} | RETIRO CORNER | Shopify #{N}"
 *   - Envio DAC:     "Cliente: {nombre} | CI: {ci} | Tel: {phone} | Dir: {dir} | CP: {cp} | ENVIO DAC | Shopify #{N}"
 *
 * NO incluye "PCS despacha al cliente" - PCS no despacha a consumidor final;
 * Corner siempre retira o usa DAC con destino del cliente final.
 */
function buildPcsComment(order, shippingMode, orderNumber) {
  const cust = order.customer || {};
  const sa   = order.shipping_address || order.billing_address || {};

  let name = `${cust.first_name || ""} ${cust.last_name || ""}`.trim();
  if (!name) name = String(sa.name || "(sin nombre)").trim();

  const parts = [`Cliente: ${name}`];

  if (shippingMode === "envia") {
    const ci    = extractCustomerCI(order);
    const phone = String(sa.phone || cust.phone || order.phone || "").trim();
    const addr1 = String(sa.address1 || "").trim();
    const addr2 = String(sa.address2 || "").trim();
    const city  = String(sa.city || "").trim();
    const prov  = String(sa.province || "").trim();
    const cp    = String(sa.zip || "").trim();

    let dir = addr1;
    if (addr2) dir += " " + addr2;
    if (city)  dir += ", " + city;
    if (prov && city.toLowerCase() !== prov.toLowerCase()) dir += ", " + prov;

    parts.push(`CI: ${ci}`);
    parts.push(`Tel: ${phone}`);
    parts.push(`Dir: ${dir}`);
    parts.push(`CP: ${cp}`);
    parts.push("ENVIO DAC");
  } else {
    parts.push("RETIRO CORNER");
  }

  parts.push(`Shopify #${orderNumber}`);

  return parts.join(" | ");
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

    const email = "ventas@corner.com.uy";

    // ── DETECTAR SHIPPING MODE desde shipping_lines ──
    const shippingMode = detectShippingMode(order);
    const shippingTitles = (order.shipping_lines || []).map((sl) => sl.title).join(", ") || "(ninguno)";
    log(`[SHIPPING] Orden #${orderNumber} shipping_lines=[${shippingTitles}] → mode="${shippingMode}"`);

    // ── Comment estructurado segun shipping mode ──
    //   retira -> solo nombre + RETIRO CORNER
    //   envia  -> cliente + CI + Tel + Dir + CP + ENVIO DAC
    const comment = buildPcsComment(order, shippingMode, orderNumber);

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

    // El comment ya viene con el formato correcto desde buildPcsComment()
    // (incluye RETIRO CORNER o ENVIO DAC segun corresponda).
    const pcsOrderId = await createPcServiceOrder({
      orderNumber,
      email,
      comment,
      items,
      shipping: shippingMode,
    });

    log(`OK → Orden #${orderNumber} enviada a PC Service. pcservice_orderid=${pcsOrderId} shipping=${shippingMode}`);

    // Guardar metafields en Shopify (orderid + shipping mode)
    await setOrderPcServiceOrderId(orderId, pcsOrderId);
    await setOrderShippingMode(orderId, shippingMode);

    return res.status(200).send("OK");
  } catch (e) {
    err(`[ERR] Webhook orders_paid topic=${topic || "-"} shop=${shop || "-"}:`, e?.message || e);
    return res.status(500).send("Error");
  }
});

// Healthcheck
app.get("/health", (_, res) => res.status(200).send("ok"));

app.listen(PORT, () => log(`Webhook vivo en puerto ${PORT}`));
