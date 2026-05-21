const DEFAULT_BLOCKED_POST_AUTH_PREFIXES = ['/auth', '/logout', '/maintenance', '/high-traffic', '/suspended'];
const DEFAULT_LEGACY_DEBUG_STORAGE_KEY = 'panom:subdomain-debug';
const DEFAULT_DEBUG_STORAGE_KEY = 'subdomain-policy:debug';

function safeLocationValue(getter, fallback) {
  try {
    const value = getter?.();
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function safeString(value, fallback = '') {
  return typeof value === 'string' ? value : fallback;
}

function safeOrigin(origin, fallbackOrigin = 'http://localhost') {
  try {
    return new URL(origin).origin;
  } catch {
    return fallbackOrigin;
  }
}

function buildOriginForHostname(currentOrigin, hostname, isDev) {
  if (isDev) return safeOrigin(currentOrigin);

  try {
    const url = new URL(safeOrigin(currentOrigin));
    url.hostname = hostname;
    url.port = '';
    return url.origin;
  } catch {
    return safeOrigin(currentOrigin);
  }
}

function buildAbsoluteUrl(currentOrigin, hostname, path, isDev) {
  return new URL(path, `${buildOriginForHostname(currentOrigin, hostname, isDev)}/`).toString();
}

function isBlockedPostAuthPath(pathname) {
  return DEFAULT_BLOCKED_POST_AUTH_PREFIXES.some(
    prefix => pathname === prefix || pathname.startsWith(`${prefix}/`) || pathname.startsWith(`${prefix}?`)
  );
}

function getStorageItem(storage, key) {
  try {
    return storage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function setStorageItem(storage, key, value) {
  try {
    storage?.setItem(key, value);
  } catch {
    // Ignore storage failures in non-browser or privacy-restricted contexts.
  }
}

function removeStorageItem(storage, key) {
  try {
    storage?.removeItem(key);
  } catch {
    // Ignore storage failures in non-browser or privacy-restricted contexts.
  }
}

export function createRouteSet(...routeNames) {
  return new Set(routeNames);
}

export function extractQueryAndHash(fullPath) {
  const queryIndex = fullPath.indexOf('?');
  const hashIndex = fullPath.indexOf('#');
  const firstIndex =
    queryIndex === -1
      ? hashIndex
      : hashIndex === -1
        ? queryIndex
        : Math.min(queryIndex, hashIndex);

  return firstIndex === -1 ? '' : fullPath.slice(firstIndex);
}

export function createSubdomainPolicyRegistry() {
  const registeredPolicies = [];

  const registry = {
    register(policy) {
      const existing = registeredPolicies.find(entry => entry.subdomain === policy.subdomain);
      if (existing) {
        throw new Error(`Duplicate subdomain policy registration: ${policy.subdomain}`);
      }

      registeredPolicies.push(policy);
      return registry;
    },
    all() {
      return registeredPolicies;
    },
    bySubdomain(subdomain) {
      return registeredPolicies.find(policy => policy.subdomain === subdomain) ?? null;
    },
    forRouteName(routeName) {
      if (typeof routeName !== 'string') return null;
      return registeredPolicies.find(policy => policy.matchRoutes.has(routeName)) ?? null;
    },
  };

  return registry;
}

export function registerSubdomainPolicies(registry, policies) {
  for (const policy of policies) {
    registry.register(policy);
  }
  return registry;
}

function buildPolicyForDefinition(definition) {
  return {
    subdomain: definition.subdomain,
    rootRenderRoute: definition.rootRenderRoute,
    canonicalPathPrefix: definition.canonicalPathPrefix,
    requiresAuth: definition.requiresAuth,
    reachableDirectly: definition.reachableDirectly,
    matchRoutes: createRouteSet(...definition.routeNames),
    socketOriginStrategy: definition.socketOriginStrategy,
    canUseProfileStyle: definition.canUseProfileStyle ?? true,
    buildCanonicalUrl(route) {
      const path = extractQueryAndHash(route.fullPath);
      if (definition.landingStrategy === 'root-only') {
        return `/${path}`;
      }
      if (definition.landingStrategy === 'root-for-landing' && route.name === definition.rootRenderRoute) {
        return `/${path}`;
      }
      return route.fullPath;
    },
  };
}

function getAllowedHostnames(rootHostname, registry, isDev, currentHostname) {
  if (isDev) return new Set([currentHostname]);

  return new Set([
    rootHostname,
    ...registry.all().map(policy => `${policy.subdomain}.${rootHostname}`),
  ]);
}

function resolveSafePostAuthRedirect({
  raw,
  rootHostname,
  registry,
  isDev,
  currentOrigin,
  currentHostname,
  currentSearch,
  getLocalStorage,
}) {
  if (!raw) return null;

  if (raw.startsWith('/')) {
    if (isBlockedPostAuthPath(raw)) return null;
    return { type: 'internal', to: raw };
  }

  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol)) return null;

    const allowedHostnames = getAllowedHostnames(rootHostname, registry, isDev, currentHostname);
    if (!allowedHostnames.has(url.hostname)) return null;
    if (isBlockedPostAuthPath(url.pathname)) return null;

    if (url.origin === currentOrigin) {
      return { type: 'internal', to: `${url.pathname}${url.search}${url.hash}` };
    }

    return { type: 'external', to: url.toString() };
  } catch {
    return null;
  }
}

export function createSubdomainPolicyRuntime({
  rootHostname,
  policies = [],
  registry: providedRegistry,
  isDev = false,
  rootRouteName = 'home',
  getCurrentOrigin,
  getCurrentHostname,
  getCurrentSearch,
  getBaseServerOrigin,
  getSessionStorage,
  getLocalStorage,
  logger = console,
} = {}) {
  if (!rootHostname) {
    throw new Error('createSubdomainPolicyRuntime requires a rootHostname');
  }

  const registry = providedRegistry ?? createSubdomainPolicyRegistry();
  if (policies.length > 0) {
    registerSubdomainPolicies(registry, policies.map(buildPolicyForDefinition));
  }

  const currentOriginGetter = () =>
    safeOrigin(
      safeLocationValue(getCurrentOrigin, safeLocationValue(() => globalThis.location?.origin, 'http://localhost'))
    );
  const currentHostnameGetter = () =>
    safeString(
      safeLocationValue(getCurrentHostname, safeLocationValue(() => globalThis.location?.hostname, '')),
      ''
    );
  const currentSearchGetter = () =>
    safeString(
      safeLocationValue(getCurrentSearch, safeLocationValue(() => globalThis.location?.search, '')),
      ''
    );
  const baseServerOriginGetter = () =>
    safeOrigin(
      safeLocationValue(getBaseServerOrigin, currentOriginGetter())
    );
  const sessionStorageGetter = () => safeLocationValue(getSessionStorage, globalThis.sessionStorage ?? null);
  const localStorageGetter = () => safeLocationValue(getLocalStorage, globalThis.localStorage ?? null);

  function getPolicyForHostname(hostname) {
    return registry.all().find(policy => hostname === `${policy.subdomain}.${rootHostname}`) ?? null;
  }

  function getPolicyForRouteName(routeName) {
    return registry.forRouteName(routeName);
  }

  function getRootRenderRouteName(hostname) {
    return getPolicyForHostname(hostname)?.rootRenderRoute ?? null;
  }

  function isRouteHandledBySubdomain(routeName, subdomain) {
    return getPolicyForRouteName(routeName)?.subdomain === subdomain;
  }

  function getPolicyLandingUrl(subdomain) {
    const policy = registry.bySubdomain(subdomain);
    if (!policy) throw new Error(`Unknown subdomain policy: ${subdomain}`);
    if (isDev) return policy.canonicalPathPrefix;
    return buildAbsoluteUrl(currentOriginGetter(), `${policy.subdomain}.${rootHostname}`, '/', isDev);
  }

  function getPolicyLandingUrlForRoute(routeName) {
    const policy = getPolicyForRouteName(routeName);
    if (!policy) throw new Error(`No subdomain policy found for route: ${String(routeName)}`);
    return getPolicyLandingUrl(policy.subdomain);
  }

  function buildAbsolutePolicyUrlForRoute(routeName, path = '/') {
    const policy = getPolicyForRouteName(routeName);
    if (!policy) throw new Error(`No subdomain policy found for route: ${String(routeName)}`);

    if (isDev) {
      const resolvedPath =
        path === '/' && routeName === policy.rootRenderRoute
          ? policy.canonicalPathPrefix
          : path;
      return new URL(resolvedPath, `${currentOriginGetter()}/`).toString();
    }

    return new URL(path, `${getPolicyLandingUrl(policy.subdomain)}/`).toString();
  }

  function getPreferredInternalPathForRoute(routeName) {
    const policy = getPolicyForRouteName(routeName);
    if (!policy) return null;

    const currentHostPolicy = getPolicyForHostname(currentHostnameGetter());
    if (currentHostPolicy?.subdomain === policy.subdomain && routeName === policy.rootRenderRoute) {
      return '/';
    }

    if (routeName === policy.rootRenderRoute) {
      return policy.canonicalPathPrefix;
    }

    return null;
  }

  function getMainAppUrl(path = '/') {
    if (isDev) return path;
    return buildAbsoluteUrl(currentOriginGetter(), rootHostname, path, isDev);
  }

  function getSocketServerOrigin(routeName) {
    const policy = getPolicyForHostname(currentHostnameGetter()) ?? getPolicyForRouteName(routeName);
    const baseOrigin = baseServerOriginGetter();

    if (!policy || isDev || policy.socketOriginStrategy === 'same-origin') {
      return baseOrigin;
    }

    try {
      const url = new URL(baseOrigin);
      url.hostname = rootHostname;
      url.port = '';
      return url.origin;
    } catch {
      return baseOrigin;
    }
  }

  function getAuthEntryUrl() {
    if (isDev) return '/auth';
    return getMainAppUrl('/auth');
  }

  function getPostAuthReturnUrl(policy, route) {
    const hostname = isDev ? currentHostnameGetter() : `${policy.subdomain}.${rootHostname}`;
    return buildAbsoluteUrl(currentOriginGetter(), hostname, policy.buildCanonicalUrl(route), isDev);
  }

  function rememberPostAuthRedirect(target) {
    setStorageItem(sessionStorageGetter(), 'subdomain-policy:post-auth-redirect', target);
  }

  function peekSafePostAuthRedirect() {
    return resolveSafePostAuthRedirect({
      raw: getStorageItem(sessionStorageGetter(), 'subdomain-policy:post-auth-redirect'),
      rootHostname,
      registry,
      isDev,
      currentOrigin: currentOriginGetter(),
      currentHostname: currentHostnameGetter(),
      currentSearch: currentSearchGetter(),
      getLocalStorage: localStorageGetter,
    });
  }

  function consumeSafePostAuthRedirect() {
    const storage = sessionStorageGetter();
    const raw = getStorageItem(storage, 'subdomain-policy:post-auth-redirect');
    removeStorageItem(storage, 'subdomain-policy:post-auth-redirect');
    return resolveSafePostAuthRedirect({
      raw,
      rootHostname,
      registry,
      isDev,
      currentOrigin: currentOriginGetter(),
      currentHostname: currentHostnameGetter(),
      currentSearch: currentSearchGetter(),
      getLocalStorage: localStorageGetter,
    });
  }

  function isSubdomainDebugEnabled() {
    const currentSearch = currentSearchGetter();
    if (typeof currentSearch === 'string' && currentSearch.length > 0) {
      try {
        const params = new URLSearchParams(currentSearch);
        if (params.get('subdomainDebug') === '1') return true;
      } catch {
        // Ignore malformed query strings.
      }
    }

    const storage = localStorageGetter();
    return (
      getStorageItem(storage, DEFAULT_DEBUG_STORAGE_KEY) === '1' ||
      getStorageItem(storage, DEFAULT_LEGACY_DEBUG_STORAGE_KEY) === '1'
    );
  }

  function logSubdomainDebug(event, payload) {
    if (!isSubdomainDebugEnabled()) return;
    logger.info(`[subdomain-debug:${event}]`, payload);
  }

  function getCanonicalNavigationTarget(hostname, route) {
    if (isDev) return null;

    const hostPolicy = getPolicyForHostname(hostname);
    const routePolicy = getPolicyForRouteName(route.name);

    if (hostPolicy && route.name === rootRouteName) {
      logSubdomainDebug('canonical-home-root', {
        hostname,
        routeName: route.name,
        fullPath: route.fullPath,
        hostPolicy: hostPolicy.subdomain,
      });
      return null;
    }

    if (hostPolicy && !routePolicy) {
      const target = {
        type: 'external',
        to: getMainAppUrl(route.fullPath),
      };
      logSubdomainDebug('canonical-nonowned-route', {
        hostname,
        routeName: route.name,
        fullPath: route.fullPath,
        hostPolicy: hostPolicy.subdomain,
        target,
      });
      return target;
    }

    if (!routePolicy) {
      logSubdomainDebug('canonical-no-policy', {
        hostname,
        routeName: route.name,
        fullPath: route.fullPath,
        hostPolicy: hostPolicy?.subdomain ?? null,
      });
      return null;
    }

    const canonicalPath = routePolicy.buildCanonicalUrl(route);

    if (hostPolicy?.subdomain === routePolicy.subdomain) {
      if (canonicalPath !== route.fullPath) {
        const target = { type: 'internal', to: canonicalPath };
        logSubdomainDebug('canonical-internal-normalize', {
          hostname,
          routeName: route.name,
          fullPath: route.fullPath,
          hostPolicy: hostPolicy.subdomain,
          routePolicy: routePolicy.subdomain,
          canonicalPath,
          target,
        });
        return target;
      }

      logSubdomainDebug('canonical-owned-route-ok', {
        hostname,
        routeName: route.name,
        fullPath: route.fullPath,
        hostPolicy: hostPolicy.subdomain,
        routePolicy: routePolicy.subdomain,
        canonicalPath,
      });
      return null;
    }

    const target = {
      type: 'external',
      to: buildAbsoluteUrl(currentOriginGetter(), `${routePolicy.subdomain}.${rootHostname}`, canonicalPath, isDev),
    };
    logSubdomainDebug('canonical-cross-host', {
      hostname,
      routeName: route.name,
      fullPath: route.fullPath,
      hostPolicy: hostPolicy?.subdomain ?? null,
      routePolicy: routePolicy.subdomain,
      canonicalPath,
      target,
    });
    return target;
  }

  return {
    rootHostname,
    registry,
    createRouteSet,
    extractQueryAndHash,
    getPolicyForHostname,
    getPolicyForRouteName,
    getRootRenderRouteName,
    isRouteHandledBySubdomain,
    getPolicyLandingUrl,
    getPolicyLandingUrlForRoute,
    buildAbsolutePolicyUrlForRoute,
    getPreferredInternalPathForRoute,
    getMainAppUrl,
    getSocketServerOrigin,
    getAuthEntryUrl,
    getPostAuthReturnUrl,
    rememberPostAuthRedirect,
    peekSafePostAuthRedirect,
    consumeSafePostAuthRedirect,
    getCanonicalNavigationTarget,
    isSubdomainDebugEnabled,
    logSubdomainDebug,
  };
}
