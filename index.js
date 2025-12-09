const express = require('express');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());

// ====== TUS DATOS (cambiá cuando tengas el usuario real) ======
const QP_USERNAME = 'testws';
const QP_PASSWORD = '12345678';
const QP_BASE     = 'https://www.pcservice.com.uy/rest';
// =============================================================

async function getQpToken() {
  const r = await fetch(`${QP_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: QP_USERNAME, password: QP_PASSWORD })
  });
  const j = await r.json();
  return j.token;
}

app.post('/webhook/orders', async (req, res) => {
  try {
    const order = req.body;
    if (!['paid', 'partially_paid'].includes(order.financial_status)) {
      return res.status(200).send('No pagada');
    }

    // Solo productos de PCService
    const pcserviceItems = order.line_items.filter(i => i.vendor === 'PCService' && i.sku);
    if (pcserviceItems.length === 0) {
      console.log(`Orden #${order.order_number} sin productos PCService → ignorada`);
      return res.status(200).send('Sin productos');
    }

    const token = await getQpToken();
    const payload = {
      description: `Orden Shopify #${order.order_number}`,
      email: order.customer?.email || 'sin@email.com',
      comment: `Cliente: ${order.customer?.first_name || ''} ${order.customer?.last_name || ''}`,
      items: pcserviceItems.map(i => ({ productId: i.sku, quantity: i.quantity })),
      extraData: { shipping: 'envia' }
    };

    const r = await fetch(`${QP_BASE}/orders/express_checkout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (r.ok) {
      console.log(`OK → Orden #${order.order_number} enviada a PCService`);
    } else {
      console.error('Error QP:', await r.text());
    }

    res.status(200).send('OK');
  } catch (e) {
    console.error('Error:', e);
    res.status(500).send('Error');
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Webhook vivo en puerto ${port}`));
