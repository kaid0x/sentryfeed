# Visitor analytics

SentryFeed uses Vercel Web Analytics through its plain-HTML integration, without npm or a build step. The scripts load only when VERCEL=1 and VERCEL_ENV=production. Both scripts carry the response's CSP nonce; the existing same-origin connection policy remains unchanged.

The beforeSend hook removes query strings and fragments from page URLs and drops /tasks/ events. No custom events are added: passwords, headers, reports, storage records, watch words and tool results are not included by this integration. The provider script runs in the page context; its behaviour remains a dependency on Vercel. This is aggregate visitor analytics, not a security audit trail or exact count of people. Blockers and disabled JavaScript can prevent collection.

## Activate

In the Vercel SentryFeed project, open Analytics and enable Web Analytics on the existing Hobby plan. Then deploy the commit containing this integration. Check the live page for the nonce-bearing /_vercel/insights/script.js tag, confirm that script loads and page-view delivery succeeds, and check the dashboard for incoming data. A local render alone does not establish collection works in production.

Tracking starts after activation and deployment; past traffic cannot be reconstructed by installing this script. Vercel's published Hobby allowance at implementation is 50,000 events per monthly cycle across the team, with a one-month reporting window. Do not enable a paid upgrade or add-on. Check the current dashboard limits when activating.

Sources:
- https://vercel.com/docs/analytics/quickstart
- https://vercel.com/docs/analytics/redacting-sensitive-data
- https://vercel.com/docs/analytics/limits-and-pricing
- https://vercel.com/docs/analytics/using-web-analytics
