# `@panomapp/subdomain-policy`

Subdomain policy utilities for host-aware routing, canonical navigation, and redirect safety.

This package is designed for public npm consumption and is framework-neutral. It provides the policy primitives and runtime helpers needed to map routes to hosts, normalize canonical URLs, and safely handle post-auth redirects.

## Installation

```bash
npm install @panomapp/subdomain-policy
```

## Exports

### `@panomapp/subdomain-policy`

Core policy primitives:

- `createRouteSet()`
- `extractQueryAndHash()`
- `createSubdomainPolicyRegistry()`
- `registerSubdomainPolicies()`
- `createSubdomainPolicyRuntime()`

### `@panomapp/subdomain-policy/runtime`

Runtime-oriented entrypoint for browser or app integration:

- policy lookup helpers
- canonical URL helpers
- redirect safety helpers
- socket origin helpers
- debug logging helpers

## Quick Start

```ts
import {
  createSubdomainPolicyRuntime,
  createRouteSet,
} from '@panomapp/subdomain-policy/runtime';

const runtime = createSubdomainPolicyRuntime({
  rootHostname: 'example.com',
  rootRouteName: 'home',
  policies: [
    {
      subdomain: 'app',
      rootRenderRoute: 'home',
      canonicalPathPrefix: '/app',
      requiresAuth: true,
      reachableDirectly: true,
      routeNames: ['home', 'settings'],
      landingStrategy: 'root-for-landing',
      socketOriginStrategy: 'root-origin',
    },
  ],
});

const appRoutes = createRouteSet('home', 'settings', 'profile');

const policy = runtime.getPolicyForHostname('app.example.com');
const landingUrl = runtime.getPolicyLandingUrl('app');
```

## Typical Responsibilities

- map hostnames to policy definitions
- determine the policy for a route name
- build canonical URLs for policy-owned routes
- choose the correct public landing URL
- validate and consume post-auth redirects
- resolve the socket server origin for a route

## Package Notes

- No product-specific sample policies are bundled.
- The package is intended to be consumed by applications that define their own subdomain policy definitions.
- The `runtime` entrypoint is the recommended import for browser-based integrations.

## Publishing

This package is published as `@panomapp/subdomain-policy` with public npm access.

```bash
npm run pack:check
npm publish --access public
```
