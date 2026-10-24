/**
 * RESILIX Central Typed API Client
 * Communicates with FastAPI backend (/api/v1) using HTTP-only session cookies
 * and in-memory session token (never persists sensitive tokens in localStorage).
 * Includes automatic Canvas sandbox fallback adapter when running inside an isolated preview iframe.
 */

let inMemoryAccessToken: string | null = null;
let inMemoryCsrfToken: string | null = null;

export function setAuthTokens(accessToken: string | null, csrfToken: string | null = null): void {
  inMemoryAccessToken = accessToken;
  inMemoryCsrfToken = csrfToken;
}

export function getAuthToken(): string | null {
  return inMemoryAccessToken;
}

export async function apiRequest<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };

  if (inMemoryAccessToken) {
    headers['Authorization'] = `Bearer ${inMemoryAccessToken}`;
  }
  if (inMemoryCsrfToken) {
    headers['X-CSRF-Token'] = inMemoryCsrfToken;
  }

  const response = await fetch(`/api/v1${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === 'string'
          ? errJson.detail
          : JSON.stringify(errJson.detail);
      }
    } catch {
      // Ignore JSON parse error
    }
    throw new Error(errorDetail);
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('text/csv')) {
    return (await response.text()) as unknown as T;
  }
  return (await response.json()) as T;
}
