import { config } from '../config';
import { createSignedToken } from './signed-token.util';

const ROUTE_PREFIX = 'payment-link';
const DEFAULT_GLOBAL_PREFIX = 'api';
const PLACEHOLDER_HOSTS = new Set(['example.com', 'example.org', 'example.net']);

function sanitizeBase(base: string): string {
  return base.replace(/\/+$/, '');
}

function isPlaceholderBase(base: string): boolean {
  if (!base) {
    return false;
  }

  try {
    const parsed = new URL(base);
    return PLACEHOLDER_HOSTS.has(parsed.hostname.toLowerCase());
  } catch {
    return /example\.(com|org|net)/i.test(base);
  }
}

function buildBaseUrl(origin: string, globalPrefix?: string): string {
  if (globalPrefix) {
    return `${origin}/${globalPrefix}/${ROUTE_PREFIX}`;
  }

  return `${origin}/${ROUTE_PREFIX}`;
}

function extractGlobalPrefix(url: URL): string | undefined {
  const configuredPrefix = config.API_PREFIX?.trim();
  if (configuredPrefix) {
    return configuredPrefix;
  }

  const pathSegments = url.pathname.split('/').filter(Boolean);
  const firstSegment = pathSegments[0];

  if (firstSegment === ROUTE_PREFIX) {
    return undefined;
  }

  if (firstSegment) {
    return firstSegment;
  }

  return DEFAULT_GLOBAL_PREFIX;
}

export function resolvePaymentLinkBase(): string | undefined {
  const explicitBase = config.PAYMENT_LINK_BASE_URL?.trim();
  if (explicitBase) {
    return sanitizeBase(explicitBase);
  }

  const fallbackCandidates = [
    process.env.BASE_PAYMENT_LINK_URL,
    process.env.BASE_CLICK_URL,
    process.env.BASE_PAYME_URL,
    process.env.BASE_UZCARD_ONETIME_URL,
  ];

  for (const candidate of fallbackCandidates) {
    if (!candidate) {
      continue;
    }

    try {
      const url = new URL(candidate);
      const prefix = extractGlobalPrefix(url);
      return sanitizeBase(buildBaseUrl(url.origin, prefix));
    } catch {
      continue;
    }
  }

  return undefined;
}

export function buildMaskedPaymentLink(path: string): string | undefined {
  const base = resolvePaymentLinkBase();
  if (!base) {
    return undefined;
  }

  const trimmedPath = path.replace(/^\/+/, '');
  return `${base}/${trimmedPath}`;
}

function deriveApiBaseFromPaymentLink(paymentLinkBase: string): string | undefined {
  try {
    const url = new URL(paymentLinkBase);
    const segments = url.pathname.split('/').filter(Boolean);

    if (segments.length && segments[segments.length - 1] === ROUTE_PREFIX) {
      segments.pop();
      url.pathname = segments.length ? `/${segments.join('/')}` : '/';
    }

    return sanitizeBase(url.toString());
  } catch {
    return undefined;
  }
}

export function resolveSubscriptionManagementBase(): string | undefined {
  const explicitBases = [
    config.SUBSCRIPTION_BASE_URL?.trim(),
    config.SUBSCRIPTION_MANAGEMENT_BASE_URL?.trim(),
  ];

  for (const rawBase of explicitBases) {
    if (!rawBase) {
      continue;
    }

    const sanitized = sanitizeBase(rawBase);
    if (isPlaceholderBase(sanitized)) {
      continue;
    }

    return sanitized;
  }

  const paymentBase = resolvePaymentLinkBase();
  if (!paymentBase) {
    return undefined;
  }

  return deriveApiBaseFromPaymentLink(paymentBase);
}

export function buildSubscriptionManagementLink(path: string): string | undefined {
  const base = resolveSubscriptionManagementBase();
  if (!base) {
    return undefined;
  }

  const trimmedPath = path.replace(/^\/+/, '');
  return `${base}/${trimmedPath}`;
}

export function buildSubscriptionCancellationLink(telegramId: number | string): string | undefined {
  if (!telegramId) {
    return undefined;
  }

  const base = resolveSubscriptionManagementBase();
  if (!base) {
    return undefined;
  }

  const token = createSignedToken(
    { telegramId: String(telegramId) },
    config.PAYMENT_LINK_SECRET,
  );

  return `${base}/subscription/cancel?token=${encodeURIComponent(token)}`;
}
