# Contributing

1. Create a focused branch from `main`.
2. Keep authority, runtime, provider, and product-plane boundaries explicit.
3. Add tests for every fail-closed path or trust-boundary change.
4. Run `npm run check`, the relevant evaluator suites, and `npm run check:secrets`.
5. Do not commit `.env.local`, credentials, runtime state, generated containers,
   or raw rejected candidate payloads.
6. Describe verified behavior separately from planned behavior in pull requests.
