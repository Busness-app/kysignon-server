let csrfTokenCache: string | null = null;

export async function fetchCSRF(forceRefresh = false): Promise<string> {
  if (forceRefresh) csrfTokenCache = null;
  if (csrfTokenCache) return csrfTokenCache;
  const res = await fetch('/api/auth/csrf');
  if (!res.ok) throw new Error('Failed to obtain CSRF token');
  const data = await res.json();
  csrfTokenCache = data.csrfToken;
  return data.csrfToken;
}

export async function apiRequest<T = any>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const method = options.method || 'GET';
  const isMutating = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';

  const send = async (refreshCSRF = false) => {
    const headers = new Headers(options.headers || {});
    if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
      headers.set('Content-Type', 'application/json');
    }
    if (isMutating) {
      const csrf = await fetchCSRF(refreshCSRF);
      headers.set('X-CSRF-Token', csrf);
    }
    return fetch(path, {
      ...options,
      headers,
      credentials: 'same-origin',
    });
  };

  let res = await send(false);

  if (res.status === 401 && !path.startsWith('/api/auth/login')) {
    // Session unauthorized
    window.dispatchEvent(new CustomEvent('kysignon:unauthorized'));
  }

  const text = await res.text();
  let data: any = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }

  if (isMutating && res.status === 403 && data.error === 'invalid_csrf') {
    res = await send(true);
    const retryText = await res.text();
    data = {};
    if (retryText) {
      try {
        data = JSON.parse(retryText);
      } catch {
        data = { raw: retryText };
      }
    }
  }

  if (!res.ok) {
    const msg = data.error_description || data.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }

  return data;
}
