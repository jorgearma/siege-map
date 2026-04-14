/**
 * KNOWN REAL ROUTES
 * ─────────────────
 * Edit this list to match the legitimate routes of YOUR application.
 * Any HTTP route that appears in the logs and is NOT listed here will
 * be classified as a BOT probe in the HTTP_ROUTES panel.
 *
 * Rules:
 *  - Add the path exactly as it appears in your access log (leading slash included)
 *  - Prefix matching: "/dashboard" will match "/dashboard", "/dashboard/metricas", etc.
 *    Set prefixMatch = false to require exact match only.
 */

export const KNOWN_ROUTES = [
  '/landing/menu-preview.html',
  '/demo',
  '/repartidor/demo',
  '/dashboard/demo',
  '/picker/demo',
  '/repartidor',
  '/picker',
  '/dashboard/pedidos-activos',
  '/dashboard/metricas',
  '/dashboard/repartidores',
  '/dashboard/eventos',
  '/dashboard/picking',
  '/dashboard/alertas',
  '/picker/cola',
  '/picker/mis-pedidos',
  '/repartidor/mis-pedidos',
  '/repartidor/cola',
  '/about',
  '/por-que-funciona',
]

/**
 * If true, "/dashboard" in the list above will also match
 * "/dashboard/anything". Set to false for exact match only.
 */
export const PREFIX_MATCH = true

export function isKnownRoute(path) {
  if (!path) return false
  const clean = path.split('?')[0].split(' ')[0] // strip query string and method prefix
  if (PREFIX_MATCH) {
    return KNOWN_ROUTES.some(
      (r) => clean === r || clean.startsWith(r + '/') || clean.startsWith(r + '?')
    )
  }
  return KNOWN_ROUTES.includes(clean)
}
