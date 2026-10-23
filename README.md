# Whisper Rose

A storefront for the Whisper Rose product catalog, account pages, and checkout flow. Accounts are stored in PostgreSQL through the Node server.

## Local development

Create a PostgreSQL database, then set `DATABASE_URL` to its connection string. Start the app with:

In PowerShell, set the connection string for the current terminal (replace the database name, user, and password as needed):

```powershell
$env:DATABASE_URL = "postgres://postgres:your-password@localhost:5432/whisper_rose"
$env:PAYSTACK_SECRET_KEY = "sk_test_your_paystack_secret_key"
$env:APP_BASE_URL = "http://localhost:3000"
```

Make sure PostgreSQL is running, then run:

```bash
npm install
npm start
```

Then visit http://localhost:3000. The server creates the account, session, and order tables on startup.

Checkout redirects customers to Paystack-hosted payment. The `pk_` public key cannot initialize server transactions; set the matching `sk_test_` secret locally and the `sk_live_` secret in Render. Never put a Paystack secret key in HTML, JavaScript, or source control. The server calculates prices and only marks orders paid after verifying the Paystack transaction. For production, configure the webhook URL in Paystack as `https://your-domain/api/payments/paystack/webhook`; Render supplies the callback base URL automatically.

Opening pages directly with `file://` does not support checkout. The storefront and checkout must be served by this Node app so authenticated payment endpoints can reach the server.

## Deploy to Render

1. Push this project to a GitHub repository.
2. In Render, create a Blueprint from that repository.
3. Render reads `render.yaml` to create the Node web service and PostgreSQL database.
4. Set the `PAYSTACK_SECRET_KEY` environment variable in the Render service using the live secret from your Paystack dashboard. The `render.yaml` blueprint prompts for this secret; it is not stored in the repository.

The free Render database is temporary and expires according to Render's free-tier policy. Choose a paid database plan for production accounts that must persist. Password reset and social sign-in remain disabled for database accounts until verified recovery and server-side provider verification are configured.
