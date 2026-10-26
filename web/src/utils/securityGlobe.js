import land from '../assets/globe/land.json'

const RAD = Math.PI / 180
const TAU = Math.PI * 2
export const EVENT_COLORS = { critical: '#ff887b', high: '#efbe64', medium: '#62e0c0', low: '#70bcc7', info: '#89afb9', unknown: '#a99bbd' }
const vector = ([lon, lat]) => [Math.cos(lat * RAD) * Math.sin(lon * RAD), Math.sin(lat * RAD), Math.cos(lat * RAD) * Math.cos(lon * RAD)]
const coasts = land.coasts.map(ring => ring.map(vector))
const dots = land.dots.map(vector)
const grids = []
for (let lat = -60; lat <= 60; lat += 30) grids.push(Array.from({ length: 73 }, (_, i) => vector([i * 5 - 180, lat])))
for (let lon = -180; lon < 180; lon += 30) grids.push(Array.from({ length: 37 }, (_, i) => vector([lon, i * 5 - 90])))

function hash(value) {
  let n = 2166136261
  for (const char of String(value)) n = Math.imul(n ^ char.charCodeAt(0), 16777619)
  return n >>> 0
}

// No geographic attribution is available. These are bounded, schematic paths
// attached to actual event identities, never fabricated source/destination data.
export function eventRoutes(events) {
  return events.slice(0, 10).map(event => {
    const seed = hash(`${event.id}:${event.host}`), target = hash(event.host)
    const a = (seed % 360) * RAD
    const b = a + (95 + target % 105) * RAD
    const start = [Math.cos(a) * .84, Math.sin(a) * .63]
    const end = [Math.cos(b) * .55, Math.sin(b) * .48]
    return { id: event.id, start, end, color: EVENT_COLORS[event.sev] || EVENT_COLORS.unknown,
      bend: seed % 2 ? .32 : -.32, period: 3.6 + (seed % 18) / 10, offset: (seed % 100) / 100 }
  })
}

export function createSecurityGlobe(canvas) {
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  let width = 0, height = 0, radius = 0, cx = 0, cy = 0, routes = [], ocean, atmosphere
  const tilt = .18, cosTilt = Math.cos(tilt), sinTilt = Math.sin(tilt)
  function resize(w, h, dpr = 1) {
    width = w; height = h; radius = Math.min(w * .32, h * .405); cx = w / 2; cy = h * .47
    const scale = Math.min(dpr, 1.5)
    canvas.width = Math.max(1, Math.round(w * scale)); canvas.height = Math.max(1, Math.round(h * scale))
    ctx.setTransform(scale, 0, 0, scale, 0, 0)
    ocean = ctx.createRadialGradient(cx - radius * .35, cy - radius * .4, 0, cx, cy, radius)
    ocean.addColorStop(0, '#16493f'); ocean.addColorStop(.55, '#0b302b'); ocean.addColorStop(1, '#041713')
    atmosphere = ctx.createRadialGradient(cx, cy, radius * .94, cx, cy, radius * 1.17)
    atmosphere.addColorStop(0, '#65e4bd00'); atmosphere.addColorStop(.28, '#65e4bd23'); atmosphere.addColorStop(1, '#65e4bd00')
  }
  const strokeCircle = (x, y, r, color, lineWidth = 1) => {
    ctx.beginPath(); ctx.arc(x, y, r, 0, TAU); ctx.strokeStyle = color; ctx.lineWidth = lineWidth; ctx.stroke()
  }
  const dot = (x, y, r, color) => {
    ctx.beginPath(); ctx.arc(x, y, r, 0, TAU); ctx.fillStyle = color; ctx.fill()
  }
  function render(seconds = 0) {
    if (!width || !height) return
    ctx.clearRect(0, 0, width, height)
    const rotation = -100 * RAD + seconds * .035
    const c = Math.cos(rotation), s = Math.sin(rotation)
    const project = point => {
      const x = point[0] * c + point[2] * s, z = point[2] * c - point[0] * s
      return [cx + x * radius, cy - (point[1] * cosTilt - z * sinTilt) * radius, point[1] * sinTilt + z * cosTilt]
    }
    // Orbital rings and atmosphere give depth without a WebGL context or texture.
    ctx.save(); ctx.translate(cx, cy + radius * .2); ctx.rotate(-.22)
    ctx.beginPath(); ctx.ellipse(0, 0, radius * 1.48, radius * .39, 0, 0, TAU)
    ctx.strokeStyle = '#62d8b526'; ctx.lineWidth = 1; ctx.stroke()
    ctx.setLineDash([3, 9]); ctx.beginPath(); ctx.ellipse(0, 0, radius * 1.6, radius * .45, 0, 0, TAU)
    ctx.strokeStyle = '#62d8b51b'; ctx.stroke(); ctx.restore()
    ctx.fillStyle = atmosphere; ctx.fillRect(cx - radius * 1.2, cy - radius * 1.2, radius * 2.4, radius * 2.4)
    ctx.beginPath(); ctx.arc(cx, cy, radius, 0, TAU); ctx.fillStyle = ocean; ctx.fill()

    function surfaceLine(points, color, lineWidth) {
      ctx.beginPath(); let previous
      for (const point of points) {
        const p = project(point)
        if (p[2] > .015) {
          if (previous?.[2] > .015) ctx.lineTo(p[0], p[1]); else ctx.moveTo(p[0], p[1])
        }
        previous = p
      }
      ctx.strokeStyle = color; ctx.lineWidth = lineWidth; ctx.stroke()
    }
    for (const line of grids) surfaceLine(line, '#68c9ad26', .65)
    for (const coast of coasts) surfaceLine(coast, '#69d5af76', .7)
    ctx.fillStyle = '#7ae6b9'
    for (const point of dots) {
      const p = project(point)
      if (p[2] <= .02) continue
      ctx.globalAlpha = .17 + p[2] * .55
      const size = .65 + p[2] * .55
      ctx.fillRect(p[0] - size / 2, p[1] - size / 2, size, size)
    }
    ctx.globalAlpha = 1
    strokeCircle(cx, cy, radius, '#86f2cf68', 1)
    strokeCircle(cx, cy, radius * 1.025, '#66cbb61c', .5)

    // Moving comets follow raised screen-space curves. The UI labels them as
    // schematic: geographic coordinates cannot be inferred from these events.
    for (const route of routes) {
      const a = [cx + route.start[0] * radius, cy + route.start[1] * radius]
      const b = [cx + route.end[0] * radius, cy + route.end[1] * radius]
      const middle = [(a[0] + b[0]) / 2 - (b[1] - a[1]) * route.bend,
        (a[1] + b[1]) / 2 + (b[0] - a[0]) * route.bend - radius * .24]
      const position = t => [(1 - t) ** 2 * a[0] + 2 * (1 - t) * t * middle[0] + t * t * b[0],
        (1 - t) ** 2 * a[1] + 2 * (1 - t) * t * middle[1] + t * t * b[1]]
      ctx.beginPath(); ctx.moveTo(...a); ctx.quadraticCurveTo(...middle, ...b)
      ctx.strokeStyle = route.color + '32'; ctx.lineWidth = 1; ctx.stroke()
      const progress = (seconds / route.period + route.offset) % 1
      for (let i = 14; i >= 0; i--) {
        const t = progress - i * .012
        if (t < 0) continue
        const p = position(t)
        ctx.globalAlpha = (1 - i / 15) * .95
        dot(...p, i === 0 ? 2.5 : 1.5, route.color)
      }
      ctx.globalAlpha = 1
      dot(...a, 2.4, route.color); dot(...b, 3, route.color)
      const pulse = (progress + .35) % 1
      ctx.globalAlpha = (1 - pulse) * .7
      strokeCircle(...b, 4 + pulse * 13, route.color, .8)
      ctx.globalAlpha = 1
    }
    // Small orbiting signal, distinct from event paths; present in empty state.
    const orbit = seconds * .23
    dot(cx + Math.cos(orbit) * radius * 1.1, cy + Math.sin(orbit) * radius * 1.1, 2, '#84e7cb')
    strokeCircle(cx, cy, radius * 1.1, '#72c9b316', .6)
  }
  return { resize, render, setEvents(events) { routes = eventRoutes(events) }, dispose() { routes = []; canvas.width = 1; canvas.height = 1 } }
}
