/**
 * Only allow same-site, relative post-login redirects (mirrors the backend's old `_safe_next`).
 * Anything else - absolute URLs, protocol-relative `//host`, backslash tricks - is ignored.
 */
export function safeNext(target) {
  if (typeof target !== 'string' || !target.startsWith('/')) return null
  if (target.startsWith('//') || target.includes('\\')) return null
  if (/^\/[a-z][a-z0-9+.-]*:/i.test(target)) return null
  return target
}
