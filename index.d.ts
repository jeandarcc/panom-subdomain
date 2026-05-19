export interface RouteLike {
  name?: unknown;
  fullPath: string;
  path?: string;
}

export type NavigationTarget =
  | { type: 'internal'; to: string }
  | { type: 'external'; to: string };

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface SubdomainPolicyDefinition {
  subdomain: string;
  rootRenderRoute: string;
  canonicalPathPrefix: string;
  requiresAuth: boolean;
  reachableDirectly: boolean;
  routeNames: string[];
  landingStrategy: 'root-only' | 'root-for-landing';
  socketOriginStrategy: 'same-origin' | 'root-origin';
  canUseProfileStyle?: boolean;
}

export interface SubdomainRoutePolicy {
  subdomain: string;
  rootRenderRoute: string;
  canonicalPathPrefix: string;
  requiresAuth: boolean;
  reachableDirectly: boolean;
  matchRoutes: ReadonlySet<string>;
  socketOriginStrategy: 'same-origin' | 'root-origin';
  canUseProfileStyle: boolean;
  buildCanonicalUrl: (route: Pick<RouteLike, 'name' | 'fullPath'>) => string;
}

export interface SubdomainPolicyRegistry {
  register(policy: SubdomainRoutePolicy): SubdomainPolicyRegistry;
  all(): readonly SubdomainRoutePolicy[];
  bySubdomain(subdomain: string): SubdomainRoutePolicy | null;
  forRouteName(routeName: unknown): SubdomainRoutePolicy | null;
}

export interface SubdomainPolicyRuntimeDependencies {
  rootHostname: string;
  rootRouteName?: string;
  policies?: readonly SubdomainPolicyDefinition[];
  registry?: SubdomainPolicyRegistry;
  isDev?: boolean;
  getCurrentOrigin?: () => string;
  getCurrentHostname?: () => string;
  getCurrentSearch?: () => string;
  getBaseServerOrigin?: () => string;
  getSessionStorage?: () => StorageLike | null | undefined;
  getLocalStorage?: () => StorageLike | null | undefined;
  logger?: Pick<Console, 'info'>;
}

export interface SubdomainPolicyRuntime {
  rootHostname: string;
  registry: SubdomainPolicyRegistry;
  createRouteSet: (...routeNames: string[]) => ReadonlySet<string>;
  extractQueryAndHash: (fullPath: string) => string;
  getPolicyForHostname: (hostname: string) => SubdomainRoutePolicy | null;
  getPolicyForRouteName: (routeName: unknown) => SubdomainRoutePolicy | null;
  getRootRenderRouteName: (hostname: string) => string | null;
  isRouteHandledBySubdomain: (routeName: unknown, subdomain: string) => boolean;
  getPolicyLandingUrl: (subdomain: string) => string;
  getPolicyLandingUrlForRoute: (routeName: unknown) => string;
  buildAbsolutePolicyUrlForRoute: (routeName: unknown, path?: string) => string;
  getPreferredInternalPathForRoute: (routeName: unknown) => string | null;
  getMainAppUrl: (path?: string) => string;
  getSocketServerOrigin: (routeName?: unknown) => string;
  getAuthEntryUrl: (_policy?: SubdomainRoutePolicy) => string;
  getPostAuthReturnUrl: (
    policy: SubdomainRoutePolicy,
    route: Pick<RouteLike, 'name' | 'fullPath'>
  ) => string;
  rememberPostAuthRedirect: (target: string) => void;
  peekSafePostAuthRedirect: () => NavigationTarget | null;
  consumeSafePostAuthRedirect: () => NavigationTarget | null;
  getCanonicalNavigationTarget: (
    hostname: string,
    route: Pick<RouteLike, 'name' | 'fullPath' | 'path'>
  ) => NavigationTarget | null;
  isSubdomainDebugEnabled: () => boolean;
  logSubdomainDebug: (event: string, payload: Record<string, unknown>) => void;
}

export declare function createRouteSet(...routeNames: string[]): ReadonlySet<string>;
export declare function extractQueryAndHash(fullPath: string): string;
export declare function createSubdomainPolicyRegistry(): SubdomainPolicyRegistry;
export declare function registerSubdomainPolicies(
  registry: SubdomainPolicyRegistry,
  policies: readonly SubdomainPolicyDefinition[]
): SubdomainPolicyRegistry;
export declare function createSubdomainPolicyRuntime(
  options: SubdomainPolicyRuntimeDependencies
): SubdomainPolicyRuntime;
