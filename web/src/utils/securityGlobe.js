import land from '../assets/globe/land.json'
import { vector, project as projectVector, greatCircle } from './globeGeometry.js'
import { located } from './securitySituation.js'

const RAD = Math.PI / 180
const TAU = Math.PI * 2
export const EVENT_COLORS = { critical: '#ff887b', high: '#efbe64', medium: '#62e0c0', low: '#70bcc7', info: '#89afb9', unknown: '#a99bbd' }
const coasts = land.coasts.map(ring => ring.map(vector))
const dots = land.dots.map(vector)
const grids = []
for (let lat = -60; lat <= 60; lat += 30) grids.push(Array.from({ length: 73 }, (_, i) => vector([i * 5 - 180, lat])))
for (let lon = -180; lon < 180; lon += 30) grids.push(Array.from({ length: 37 }, (_, i) => vector([lon, i * 5 - 90])))

export function eventRoutes(events) {
  return events.filter(event => event.network && event.sourceIp && located(event.sourceLocation) && located(event.targetLocation)).slice(0, 10).map(event => {
    const start = vector([event.sourceLocation.longitude, event.sourceLocation.latitude])
    const end = vector([event.targetLocation.longitude, event.targetLocation.latitude])
    return { id: event.id, start, end, color: EVENT_COLORS[event.sev] || EVENT_COLORS.unknown,
      samples: Array.from({ length: 65 }, (_, i) => greatCircle(start, end, i / 64)),
      signature: `${event.observedAt}:${event.count}` }
  })
}

export function createSecurityGlobe(canvas) {
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  let width = 0, height = 0, radius = 0, cx = 0, cy = 0, routes = [], markers = [], ocean, atmosphere
  let snapshotSeen = false, selected, stale = false, lastSeconds = 0, hits = []
  const signatures = new Map(), pulses = new Map(), pending = new Map()
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
    lastSeconds = seconds; hits = []
    const rotation = -100 * RAD + seconds * .035
    const project = point => {
      const p = projectVector(point, rotation)
      return [cx + p.x * radius, cy + p.y * radius, p.depth, p.visible]
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

    // Geography, markers and raised great-circle paths share one 3D projection.
    for (const route of routes) {
      const projected = route.samples.map(project)
      ctx.beginPath()
      let previous
      for (const p of projected) {
        if (p[3]) { if (previous?.[3]) ctx.lineTo(p[0], p[1]); else ctx.moveTo(p[0], p[1]) }
        previous = p
      }
      ctx.strokeStyle = route.color + (route.id === selected ? 'bb' : '55'); ctx.lineWidth = route.id === selected ? 1.7 : 1; ctx.stroke()
      for (const p of projected) if (p[3]) hits.push({ id: route.id, x: p[0], y: p[1] })
      // A newly observed event update emits one pulse, never an endless replay.
      const started = pulses.get(route.id)
      const progress = started == null ? -1 : (seconds - started) / 3
      if (!stale && progress >= 0 && progress <= 1) {
        for (let i = 12; i >= 0; i--) {
          const t = progress - i * .012
          if (t < 0) continue
          const p = project(greatCircle(route.start, route.end, t))
          if (!p[3]) continue
          ctx.globalAlpha = (1 - i / 13) * .95
          dot(p[0], p[1], i === 0 ? 2.7 : 1.5, route.color)
        }
      }
      ctx.globalAlpha = 1
    }
    for (const marker of markers) {
      const p = project(marker.point)
      if (p[2] <= .015) continue
      dot(p[0], p[1], marker.id === selected ? 3.8 : 2.7, marker.color)
      strokeCircle(p[0], p[1], marker.id === selected ? 8 : 5, marker.color + '80', .8)
      hits.push({ id: marker.id, x: p[0], y: p[1] })
    }
  }
  return { resize, render,
    setEvents(events, options = {}) {
      stale = !!options.stale
      routes = eventRoutes(events)
      markers = events.flatMap(event => {
        const result = [], color = EVENT_COLORS[event.sev] || EVENT_COLORS.unknown
        if (event.sourceIp && located(event.sourceLocation)) result.push({ id: event.id, point: vector([event.sourceLocation.longitude, event.sourceLocation.latitude]), color })
        if (located(event.targetLocation)) result.push({ id: event.id, point: vector([event.targetLocation.longitude, event.targetLocation.latitude]), color })
        return result
      }).slice(0, 40)
      const now = Date.now()
      if (stale) pending.clear()
      for (const event of events) {
        const signature = `${event.observedAt}:${event.count}`
        if (snapshotSeen && !stale && signatures.get(event.id) !== signature) pending.set(event.id, { signature, expires: now + 65000 })
        signatures.set(event.id, signature)
      }
      for (const route of routes) {
        const update = pending.get(route.id)
        if (update?.signature === route.signature && update.expires >= now) { pulses.set(route.id, lastSeconds); pending.delete(route.id) }
      }
      const ids = new Set(events.map(event => event.id))
      for (const id of signatures.keys()) if (!ids.has(id)) { signatures.delete(id); pulses.delete(id) }
      for (const [id, update] of pending) if (!ids.has(id) || update.expires < now) pending.delete(id)
      if (options.ready) snapshotSeen = true
    },
    select(id) { selected = id },
    pick(x, y) { return hits.find(hit => Math.hypot(hit.x - x, hit.y - y) <= 8)?.id },
    dispose() { routes = []; markers = []; hits = []; signatures.clear(); pulses.clear(); pending.clear(); canvas.width = 1; canvas.height = 1 },
  }
}
