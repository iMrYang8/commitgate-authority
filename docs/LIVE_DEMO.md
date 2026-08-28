# Live demo

Prepare the stack before presenting:

```bash
cp .env.local.example .env.local
chmod 600 .env.local
npm ci
npm run demo
```

The three-minute narrative is:

1. show the current HEAD generation and StateView;
2. show one committed proposal with trusted evidence and a consumed permit;
3. show a protected-path rejection with an unchanged HEAD;
4. replay the consumed permit through the public API and show `PERMIT_REPLAY`;
5. perform a rollback and show a new generation and immutable version event;
6. close with the exact filesystem-only and process-restart claim boundary.

Never display `.env.local`, authorization headers, provider keys, or raw runtime
secret files while recording.
