/**
 * Drop parameters that mean "not set" so URLs stay clean and the backend never sees empty
 * filters: undefined, null, empty strings and `false`. `true` is sent as the string "true".
 */
export function cleanParams(params = {}) {
  const out = {}
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '' || value === false) continue
    out[key] = value === true ? 'true' : value
  }
  return out
}
