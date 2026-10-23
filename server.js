'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT || 3000);
const iterations = 100000;
const sessionDuration = 30 * 24 * 60 * 60 * 1000;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  connectionTimeoutMillis: 5000
});

app.use(express.json({
  limit: '16kb',
  verify: (request, response, buffer) => {
    request.rawBody = Buffer.from(buffer);
  }
}));

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validEmail(value) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPassword(value) {
  return typeof value === 'string' && value.length <= 1024 && value.length >= 8 &&
    /[A-Za-z]/.test(value) && /\d/.test(value);
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (error, hash) => {
      if (error) reject(error);
      else resolve(hash.toString('base64'));
    });
  });
}

function publicAccount(row) {
  return { id: row.id, name: row.name, email: row.email, provider: row.provider };
}

async function createSession(account, remember) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + (remember ? sessionDuration : 12 * 60 * 60 * 1000));
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await pool.query(
    'INSERT INTO account_sessions (token_hash, account_id, expires_at) VALUES ($1, $2, $3)',
    [tokenHash, account.id, expiresAt]
  );
  return { token, expiresAt: expiresAt.getTime(), user: publicAccount(account) };
}

function bearerToken(request) {
  const match = /^Bearer ([a-f0-9]{64})$/i.exec(request.get('authorization') || '');
  return match ? match[1] : null;
}

async function requireAccount(request, response, next) {
  const token = bearerToken(request);
  if (!token) return response.status(401).json({ ok: false, message: 'Log in to continue.' });

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const result = await pool.query(
      `SELECT a.id, a.name, a.email
       FROM account_sessions s
       JOIN accounts a ON a.id = s.account_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [tokenHash]
    );
    if (!result.rows[0]) return response.status(401).json({ ok: false, message: 'Your session has expired. Log in again.' });
    request.account = result.rows[0];
    next();
  } catch (error) {
    console.error('Account session check failed:', error.message);
    response.status(500).json({ ok: false, message: 'Could not verify your session.' });
  }
}

function paystackSecret() {
  const secret = process.env.PAYSTACK_SECRET_KEY;
  if (!secret || !/^sk_(test|live)_/.test(secret)) {
    throw new Error('PAYSTACK_SECRET_KEY is not configured with a Paystack secret key.');
  }
  return secret;
}

function paymentCallbackUrl() {
  const configuredUrl = process.env.APP_BASE_URL || process.env.RENDER_EXTERNAL_URL;
  if (!configuredUrl) throw new Error('APP_BASE_URL is not configured.');
  const url = new URL(configuredUrl);
  const localHttp = url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname);
  if (url.protocol !== 'https:' && !localHttp) {
    throw new Error('APP_BASE_URL must use HTTPS, except for localhost development.');
  }
  return `${url.origin}/api/payments/paystack/callback`;
}

async function paystackRequest(endpoint, options = {}) {
  const response = await fetch(`https://api.paystack.co${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${paystackSecret()}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const result = await response.json();
  if (!response.ok || !result.status) {
    throw new Error(result.message || 'Paystack request failed.');
  }
  return result.data;
}

const PRODUCT = {
  id: 1,
  name: 'Bloom Rose Massager',
  priceMinor: 3900,
  image: 'https://images.unsplash.com/photo-1519058497187-7167f17c6daf?auto=format&fit=crop&w=200&q=80',
  colors: ['Ruby Red', 'Blush Pink', 'Midnight Plum']
};
const SHIPPING_COUNTRIES = new Set(['Ghana', 'Nigeria', 'United States', 'United Kingdom', 'Canada', 'South Africa', 'Other']);

function checkoutItems(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 10) return null;
  const items = [];
  let totalQuantity = 0;
  for (const item of input) {
    if (!item || typeof item !== 'object') return null;
    const quantity = Number(item.quantity);
    const color = String(item.color || '');
    if (String(item.id) !== String(PRODUCT.id) || !PRODUCT.colors.includes(color) ||
        !Number.isInteger(quantity) || quantity < 1 || quantity > 10) return null;
    totalQuantity += quantity;
    if (totalQuantity > 50) return null;
    items.push({
      id: PRODUCT.id,
      name: PRODUCT.name,
      image: PRODUCT.image,
      priceMinor: PRODUCT.priceMinor,
      color,
      quantity
    });
  }
  return items;
}

function orderTotals(items, promoCode) {
  const subtotalMinor = items.reduce((sum, item) => sum + item.priceMinor * item.quantity, 0);
  const discountMinor = promoCode === 'WELCOME10' ? Math.round(subtotalMinor * 0.1) : 0;
  const taxableMinor = subtotalMinor - discountMinor;
  const taxMinor = Math.round(taxableMinor * 0.08);
  return { subtotalMinor, discountMinor, taxMinor, amountMinor: taxableMinor + taxMinor, currency: 'GHS' };
}

function validPromoCode(value) {
  return !value || value === 'WELCOME10';
}

async function verifyPaystackOrder(reference) {
  return paystackRequest(`/transaction/verify/${encodeURIComponent(reference)}`);
}

function paidTransactionMatches(order, transaction) {
  return transaction.status === 'success' &&
    transaction.reference === order.payment_reference &&
    Number(transaction.amount) === order.amount_minor &&
    transaction.currency === order.currency &&
    normalizeEmail(transaction.customer?.email) === order.customer_email;
}

function validPaystackSignature(rawBody, signature, secret) {
  if (typeof signature !== 'string' || !/^[a-f0-9]{128}$/i.test(signature)) return false;
  const expected = crypto.createHmac('sha512', secret).update(rawBody).digest();
  const received = Buffer.from(signature, 'hex');
  return received.length === expected.length && crypto.timingSafeEqual(received, expected);
}

async function confirmPaidOrder(order, transaction) {
  if (paidTransactionMatches(order, transaction)) {
    await pool.query(
      `UPDATE payment_orders
       SET status = 'paid', paystack_transaction_id = $2, paid_at = COALESCE(paid_at, NOW())
      WHERE payment_reference = $1 AND status IN ('pending', 'review', 'failed')`,
      [order.payment_reference, String(transaction.id)]
    );
    return 'paid';
  }

  if (transaction.status === 'success') {
    await pool.query(
      `UPDATE payment_orders SET status = 'review'
       WHERE payment_reference = $1 AND status = 'pending'`,
      [order.payment_reference]
    );
    return 'review';
  }

  if (['failed', 'abandoned', 'reversed'].includes(transaction.status)) {
    await pool.query(
      `UPDATE payment_orders SET status = 'failed'
       WHERE payment_reference = $1 AND status = 'pending'`,
      [order.payment_reference]
    );
    return 'failed';
  }

  return 'pending';
}

app.get('/api/health', async (request, response) => {
  try {
    await pool.query('SELECT 1');
    response.json({ ok: true });
  } catch (error) {
    response.status(503).json({ ok: false, message: 'Database unavailable.' });
  }
});

app.post('/api/auth/signup', async (request, response) => {
  const name = String(request.body.name || '').trim();
  const email = normalizeEmail(request.body.email);
  const password = request.body.password;
  if (!name || name.length > 120) {
    return response.status(400).json({ ok: false, message: 'Enter a name of 1 to 120 characters.' });
  }
  if (!validEmail(email)) {
    return response.status(400).json({ ok: false, message: 'Enter a valid email address.' });
  }
  if (!validPassword(password)) {
    return response.status(400).json({ ok: false, message: 'Use at least 8 characters, with a letter and a number.' });
  }

  try {
    const salt = crypto.randomBytes(16).toString('base64');
    const hash = await hashPassword(password, salt);
    const result = await pool.query(
      `INSERT INTO accounts (name, email, password_salt, password_hash, provider)
       VALUES ($1, $2, $3, $4, 'password')
       RETURNING id, name, email, provider`,
      [name, email, salt, hash]
    );
    response.status(201).json({ ok: true, user: publicAccount(result.rows[0]) });
  } catch (error) {
    if (error.code === '23505') {
      return response.status(409).json({ ok: false, code: 'exists', message: 'An account with this email already exists.' });
    }
    console.error('Account signup failed:', error.message);
    response.status(500).json({ ok: false, message: 'Could not create your account. Please try again.' });
  }
});

app.post('/api/auth/login', async (request, response) => {
  const email = normalizeEmail(request.body.email);
  const password = typeof request.body.password === 'string' ? request.body.password : '';
  if (!validEmail(email) || !password || password.length > 1024) {
    return response.status(400).json({ ok: false, code: 'invalid', message: 'Incorrect email or password.' });
  }

  try {
    const result = await pool.query(
      'SELECT id, name, email, provider, password_salt, password_hash FROM accounts WHERE email = $1',
      [email]
    );
    const account = result.rows[0];
    const salt = account ? account.password_salt : 'AAAAAAAAAAAAAAAAAAAAAA==';
    const actualHash = await hashPassword(password, salt);
    const actual = Buffer.from(actualHash, 'base64');
    const expected = Buffer.from(account ? account.password_hash : actualHash, 'base64');
    const matches = actual.length === expected.length && crypto.timingSafeEqual(actual, expected);

    if (!account || !account.password_hash || !matches) {
      return response.status(401).json({ ok: false, code: 'invalid', message: 'Incorrect email or password.' });
    }
    const session = await createSession(account, request.body.remember !== false);
    response.json({ ok: true, ...session });
  } catch (error) {
    console.error('Account login failed:', error.message);
    response.status(500).json({ ok: false, message: 'Could not log in. Please try again.' });
  }
});

app.delete('/api/auth/session', async (request, response) => {
  const token = bearerToken(request);
  if (token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await pool.query('DELETE FROM account_sessions WHERE token_hash = $1', [tokenHash]);
  }
  response.status(204).end();
});

app.post('/api/payments/quote', requireAccount, (request, response) => {
  const items = checkoutItems(request.body?.items);
  const promoCode = String(request.body?.promoCode || '').trim().toUpperCase();
  if (!items) return response.status(400).json({ ok: false, message: 'Your cart is invalid. Return to the store and try again.' });
  if (!validPromoCode(promoCode)) return response.status(400).json({ ok: false, message: 'That promo code is not valid.' });
  let paymentsAvailable = false;
  try {
    paystackSecret();
    paymentCallbackUrl();
    paymentsAvailable = true;
  } catch (error) {}
  response.json({ ok: true, items, totals: orderTotals(items, promoCode), paymentsAvailable });
});

app.post('/api/payments/paystack/initialize', requireAccount, async (request, response) => {
  const body = request.body || {};
  const fullName = String(body.fullName || '').trim();
  const address1 = String(body.address1 || '').trim();
  const address2 = String(body.address2 || '').trim();
  const city = String(body.city || '').trim();
  const region = String(body.region || '').trim();
  const postal = String(body.postal || '').trim();
  const country = String(body.country || '').trim();
  const phone = String(body.phone || '').trim();
  const items = checkoutItems(body.items);
  const promoCode = String(body.promoCode || '').trim().toUpperCase();

    if (!fullName || fullName.length > 120 || !phone || !address1 || address1.length > 200 ||
      address2.length > 200 || !city || city.length > 120 || region.length > 120 ||
      !postal || postal.length > 32 || !SHIPPING_COUNTRIES.has(country) || phone.length > 32 || !items) {
    return response.status(400).json({ ok: false, message: 'Check your shipping details and cart, then try again.' });
  }
  if (!validPromoCode(promoCode)) {
    return response.status(400).json({ ok: false, message: 'That promo code is not valid.' });
  }

  let callbackUrl;
  try {
    paystackSecret();
    callbackUrl = paymentCallbackUrl();
  } catch (error) {
    return response.status(503).json({ ok: false, message: 'Online payments are not configured yet.' });
  }

  const { subtotalMinor, discountMinor, taxMinor, amountMinor } = orderTotals(items, promoCode);
  const reference = `wr-${crypto.randomBytes(16).toString('hex')}`;
  const shipping = { fullName, phone, address1, address2, city, region, postal, country };

  try {
    const inserted = await pool.query(
      `INSERT INTO payment_orders (
         account_id, payment_reference, status, customer_email, currency,
         subtotal_minor, discount_minor, tax_minor, amount_minor, items, shipping
       ) VALUES ($1, $2, 'pending', $3, 'GHS', $4, $5, $6, $7, $8, $9)
       RETURNING id`,
      [request.account.id, reference, request.account.email, subtotalMinor, discountMinor,
        taxMinor, amountMinor, JSON.stringify(items), JSON.stringify(shipping)]
    );
    const orderId = inserted.rows[0].id;
    const payment = await paystackRequest('/transaction/initialize', {
      method: 'POST',
      body: JSON.stringify({
        email: request.account.email,
        amount: String(amountMinor),
        currency: 'GHS',
        reference,
        callback_url: callbackUrl,
        metadata: { order_id: orderId }
      })
    });
    const authorizationUrl = new URL(payment.authorization_url);
    if (authorizationUrl.protocol !== 'https:' || authorizationUrl.hostname !== 'checkout.paystack.com') {
      throw new Error('Paystack returned an unexpected checkout URL.');
    }
    response.json({
      ok: true,
      authorizationUrl: authorizationUrl.toString(),
      reference,
      totals: { subtotalMinor, discountMinor, taxMinor, amountMinor, currency: 'GHS' }
    });
  } catch (error) {
    await pool.query(
      `UPDATE payment_orders SET status = 'failed' WHERE payment_reference = $1 AND status = 'pending'`,
      [reference]
    ).catch(() => {});
    console.error('Paystack initialization failed:', error.message);
    response.status(502).json({ ok: false, message: 'Could not start secure payment. Please try again.' });
  }
});

app.get('/api/payments/paystack/callback', async (request, response) => {
  const reference = String(request.query.reference || '');
  const checkoutUrl = (status) => `/checkout.html?payment=${status}`;
  if (!/^[A-Za-z0-9.=-]{8,100}$/.test(reference)) return response.redirect(checkoutUrl('failed'));

  try {
    const orderResult = await pool.query(
      'SELECT * FROM payment_orders WHERE payment_reference = $1',
      [reference]
    );
    const order = orderResult.rows[0];
    if (!order) return response.redirect(checkoutUrl('failed'));

    const transaction = await verifyPaystackOrder(reference);
    const status = await confirmPaidOrder(order, transaction);
    response.redirect(`${checkoutUrl(status)}&reference=${encodeURIComponent(reference)}`);
  } catch (error) {
    console.error('Paystack callback verification failed:', error.message);
    response.redirect(`${checkoutUrl('pending')}&reference=${encodeURIComponent(reference)}`);
  }
});

app.get('/api/orders/:reference', requireAccount, async (request, response) => {
  try {
    const result = await pool.query(
      `SELECT payment_reference, status, currency, amount_minor, items, paid_at
       FROM payment_orders WHERE payment_reference = $1 AND account_id = $2`,
      [request.params.reference, request.account.id]
    );
    if (!result.rows[0]) return response.status(404).json({ ok: false, message: 'Order not found.' });
    const order = result.rows[0];
    response.json({
      ok: true,
      order: {
        reference: order.payment_reference,
        status: order.status,
        currency: order.currency,
        amountMinor: order.amount_minor,
        items: order.items,
        paidAt: order.paid_at
      }
    });
  } catch (error) {
    console.error('Order lookup failed:', error.message);
    response.status(500).json({ ok: false, message: 'Could not load this order.' });
  }
});

app.post('/api/orders/:reference/verify', requireAccount, async (request, response) => {
  try {
    const result = await pool.query(
      'SELECT * FROM payment_orders WHERE payment_reference = $1 AND account_id = $2',
      [request.params.reference, request.account.id]
    );
    const order = result.rows[0];
    if (!order) return response.status(404).json({ ok: false, message: 'Order not found.' });
    if (order.status === 'pending' || order.status === 'review') {
      const transaction = await verifyPaystackOrder(order.payment_reference);
      await confirmPaidOrder(order, transaction);
    }
    const updated = await pool.query(
      'SELECT payment_reference, status, currency, amount_minor, items, paid_at FROM payment_orders WHERE id = $1',
      [order.id]
    );
    const current = updated.rows[0];
    response.json({
      ok: true,
      order: {
        reference: current.payment_reference,
        status: current.status,
        currency: current.currency,
        amountMinor: current.amount_minor,
        items: current.items,
        paidAt: current.paid_at
      }
    });
  } catch (error) {
    console.error('Order verification failed:', error.message);
    response.status(502).json({ ok: false, message: 'Payment is still being verified. Please check again shortly.' });
  }
});

app.post('/api/payments/paystack/webhook', async (request, response) => {
  let secret;
  try {
    secret = paystackSecret();
  } catch (error) {
    return response.status(503).end();
  }

  const signature = request.get('x-paystack-signature') || '';
  if (!validPaystackSignature(request.rawBody || Buffer.alloc(0), signature, secret)) {
    return response.status(401).end();
  }

  if (request.body?.event === 'charge.success') {
    const transaction = request.body.data || {};
    try {
      const orderResult = await pool.query(
        'SELECT * FROM payment_orders WHERE payment_reference = $1',
        [transaction.reference]
      );
      const order = orderResult.rows[0];
      if (order) await confirmPaidOrder(order, transaction);
    } catch (error) {
      console.error('Paystack webhook processing failed:', error.message);
      return response.status(500).end();
    }
  }
  response.sendStatus(200);
});

app.use(express.static(path.join(__dirname)));

async function start() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not set. Start PostgreSQL and configure DATABASE_URL before starting the server.');
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(120) NOT NULL,
      email VARCHAR(254) NOT NULL UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      provider VARCHAR(32) NOT NULL DEFAULT 'password',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS account_sessions (
      token_hash CHAR(64) PRIMARY KEY,
      account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_orders (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      account_id UUID NOT NULL REFERENCES accounts(id),
      payment_reference VARCHAR(100) NOT NULL UNIQUE,
      status VARCHAR(24) NOT NULL DEFAULT 'pending',
      customer_email VARCHAR(254) NOT NULL,
      currency CHAR(3) NOT NULL,
      subtotal_minor INTEGER NOT NULL,
      discount_minor INTEGER NOT NULL DEFAULT 0,
      tax_minor INTEGER NOT NULL,
      amount_minor INTEGER NOT NULL,
      items JSONB NOT NULL,
      shipping JSONB NOT NULL,
      paystack_transaction_id VARCHAR(32),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS payment_orders_account_created_idx ON payment_orders (account_id, created_at DESC)');
  app.listen(port, () => console.log(`Whisper Rose listening on port ${port}`));
}

if (require.main === module) {
  start().catch((error) => {
    console.error('Server startup failed:', error.message);
    process.exit(1);
  });
}

module.exports = { checkoutItems, orderTotals, paidTransactionMatches, validPaystackSignature, validPromoCode };