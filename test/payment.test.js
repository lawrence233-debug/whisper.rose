'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { checkoutItems, orderTotals, paidTransactionMatches, validPaystackSignature, validPromoCode } = require('../server');

test('checkout items use server catalog data instead of client prices', () => {
  const [item] = checkoutItems([{ id: 1, color: 'Ruby Red', quantity: 2, price: 0, name: 'Forged item' }]);

  assert.equal(item.name, 'Bloom Rose Suction Massager');
  assert.equal(item.priceMinor, 3900);
  assert.equal(item.quantity, 2);

  const products = checkoutItems([
    { id: 2, color: 'Pink', quantity: 1 },
    { id: 3, color: 'Pink and White', quantity: 1 }
  ]);
  assert.deepEqual(products.map(({ id, name, priceMinor }) => ({ id, name, priceMinor })), [
    { id: 2, name: 'Pulse Wand Massager', priceMinor: 3900 },
    { id: 3, name: 'Duo Dual-Stimulation Massager', priceMinor: 3900 }
  ]);
});

test('checkout rejects invalid colors and quantities', () => {
  assert.equal(checkoutItems([null]), null);
  assert.equal(checkoutItems([{ id: 1, color: 'Unknown', quantity: 1 }]), null);
  assert.equal(checkoutItems([{ id: 2, color: 'Ruby Red', quantity: 1 }]), null);
  assert.equal(checkoutItems([{ id: 4, color: 'Pink', quantity: 1 }]), null);
  assert.equal(checkoutItems([{ id: 1, color: 'Ruby Red', quantity: 1.5 }]), null);
  assert.equal(checkoutItems([{ id: 1, color: 'Ruby Red', quantity: 51 }]), null);
});

test('order totals use GHS minor units and match the 8 percent tax rate', () => {
  assert.deepEqual(orderTotals(checkoutItems([{ id: 1, color: 'Ruby Red', quantity: 1 }]), ''), {
    subtotalMinor: 3900,
    discountMinor: 0,
    taxMinor: 312,
    amountMinor: 4212,
    currency: 'GHS'
  });
});

test('WELCOME10 discount and promo validation are calculated on the server', () => {
  const items = checkoutItems([{ id: 1, color: 'Blush Pink', quantity: 2 }]);
  assert.deepEqual(orderTotals(items, 'WELCOME10'), {
    subtotalMinor: 7800,
    discountMinor: 780,
    taxMinor: 562,
    amountMinor: 7582,
    currency: 'GHS'
  });
  assert.equal(validPromoCode('WELCOME10'), true);
  assert.equal(validPromoCode('WELCOME100'), false);
});

test('payment is accepted only when Paystack reference, amount, currency, and email match', () => {
  const order = {
    payment_reference: 'wr-test-reference',
    amount_minor: 4212,
    currency: 'GHS',
    customer_email: 'customer@example.com'
  };
  const transaction = {
    status: 'success',
    reference: 'wr-test-reference',
    amount: 4212,
    currency: 'GHS',
    customer: { email: 'CUSTOMER@example.com' }
  };

  assert.equal(paidTransactionMatches(order, transaction), true);
  assert.equal(paidTransactionMatches(order, { ...transaction, amount: 4211 }), false);
  assert.equal(paidTransactionMatches(order, { ...transaction, currency: 'NGN' }), false);
  assert.equal(paidTransactionMatches(order, { ...transaction, reference: 'other-reference' }), false);
  assert.equal(paidTransactionMatches(order, { ...transaction, customer: { email: 'other@example.com' } }), false);
  assert.equal(paidTransactionMatches(order, { ...transaction, status: 'abandoned' }), false);
});

test('webhook signature is verified against the raw request body', () => {
  const secret = 'sk_test_example_secret';
  const rawBody = Buffer.from('{"event":"charge.success"}');
  const signature = crypto.createHmac('sha512', secret).update(rawBody).digest('hex');

  assert.equal(validPaystackSignature(rawBody, signature, secret), true);
  assert.equal(validPaystackSignature(Buffer.from('{"event":"charge.failed"}'), signature, secret), false);
  assert.equal(validPaystackSignature(rawBody, 'forged', secret), false);
});