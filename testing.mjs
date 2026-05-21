import assert from 'node:assert/strict';
import {
  createSubdomainPolicyRuntime,
  createRouteSet,
  createSubdomainPolicyRegistry,
  registerSubdomainPolicies,
} from './index.mjs';

const policies = [
  {
    subdomain: 'alpha',
    rootRenderRoute: 'alpha-home',
    canonicalPathPrefix: '/alpha',
    requiresAuth: true,
    reachableDirectly: false,
    routeNames: ['alpha-home', 'alpha-settings'],
    landingStrategy: 'root-for-landing',
    socketOriginStrategy: 'root-origin',
  },
  {
    subdomain: 'beta',
    rootRenderRoute: 'beta-home',
    canonicalPathPrefix: '/beta',
    requiresAuth: false,
    reachableDirectly: true,
    routeNames: ['beta-home'],
    landingStrategy: 'root-only',
    socketOriginStrategy: 'same-origin',
  },
];

function createMemoryStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, value);
    },
    removeItem(key) {
      map.delete(key);
    },
  };
}

const sessionStorage = createMemoryStorage();
const localStorage = createMemoryStorage();

const runtime = createSubdomainPolicyRuntime({
  rootHostname: 'example.com',
  policies,
  isDev: false,
  getCurrentOrigin: () => 'https://alpha.example.com',
  getCurrentHostname: () => 'alpha.example.com',
  getCurrentSearch: () => '',
  getBaseServerOrigin: () => 'https://api.example.com',
  getSessionStorage: () => sessionStorage,
  getLocalStorage: () => localStorage,
});

assert.equal(runtime.getPolicyForHostname('alpha.example.com')?.subdomain, 'alpha');
assert.equal(runtime.getPolicyForHostname('beta.example.com')?.subdomain, 'beta');
assert.equal(runtime.getPolicyForRouteName('beta-home')?.subdomain, 'beta');
assert.equal(runtime.getRootRenderRouteName('beta.example.com'), 'beta-home');
assert.equal(runtime.isRouteHandledBySubdomain('alpha-settings', 'alpha'), true);
assert.equal(runtime.getPolicyLandingUrl('alpha'), 'https://alpha.example.com/');
assert.equal(runtime.getPolicyLandingUrlForRoute('beta-home'), 'https://beta.example.com/');
assert.equal(runtime.getMainAppUrl('/auth'), 'https://example.com/auth');
assert.equal(runtime.getSocketServerOrigin('alpha-settings'), 'https://example.com');
assert.equal(runtime.getSocketServerOrigin('beta-home'), 'https://example.com');
assert.equal(runtime.getPreferredInternalPathForRoute('alpha-home'), '/');
assert.equal(runtime.getPreferredInternalPathForRoute('alpha-settings'), null);
assert.equal(runtime.buildAbsolutePolicyUrlForRoute('alpha-home', '/alpha/abc'), 'https://alpha.example.com/alpha/abc');
assert.equal(runtime.getPostAuthReturnUrl(runtime.getPolicyForRouteName('alpha-home'), { name: 'alpha-home', fullPath: '/alpha' }), 'https://alpha.example.com/');

runtime.rememberPostAuthRedirect('/alpha/settings');
assert.deepEqual(runtime.peekSafePostAuthRedirect(), { type: 'internal', to: '/alpha/settings' });
assert.deepEqual(runtime.consumeSafePostAuthRedirect(), { type: 'internal', to: '/alpha/settings' });
assert.equal(runtime.consumeSafePostAuthRedirect(), null);

assert.equal(runtime.getCanonicalNavigationTarget('beta.example.com', { name: 'alpha-home', fullPath: '/alpha', path: '/alpha' })?.type, 'external');
assert.deepEqual(runtime.getCanonicalNavigationTarget('alpha.example.com', { name: 'alpha-home', fullPath: '/alpha', path: '/alpha' }), {
  type: 'internal',
  to: '/',
});

assert.deepEqual([...createRouteSet('one', 'two')], ['one', 'two']);

const registry = createSubdomainPolicyRegistry();
registerSubdomainPolicies(registry, runtime.registry.all());
assert.equal(registry.bySubdomain('alpha')?.subdomain, 'alpha');

const devRuntime = createSubdomainPolicyRuntime({
  rootHostname: 'panom.app',
  policies: [
    {
      subdomain: 'cloud',
      rootRenderRoute: 'cloud.root',
      canonicalPathPrefix: '/cloud',
      requiresAuth: true,
      reachableDirectly: false,
      routeNames: ['cloud.root'],
      landingStrategy: 'root-only',
      socketOriginStrategy: 'same-origin',
    },
  ],
  isDev: true,
  getCurrentOrigin: () => 'https://dev.panom.app:3000',
  getCurrentHostname: () => 'dev.panom.app',
  getCurrentSearch: () => '',
  getBaseServerOrigin: () => 'https://dev.panom.app:3000',
  getSessionStorage: () => sessionStorage,
  getLocalStorage: () => localStorage,
});

assert.equal(devRuntime.buildAbsolutePolicyUrlForRoute('cloud.root'), 'https://dev.panom.app:3000/cloud');
assert.equal(
  devRuntime.buildAbsolutePolicyUrlForRoute('cloud.root', '/cloud/extra'),
  'https://dev.panom.app:3000/cloud/extra'
);

console.log('subdomain-policy selftest passed');
