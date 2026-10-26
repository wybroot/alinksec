const RAD = Math.PI / 180
export const vector = ([longitude, latitude]) => [Math.cos(latitude * RAD) * Math.sin(longitude * RAD), Math.sin(latitude * RAD), Math.cos(latitude * RAD) * Math.cos(longitude * RAD)]
export function project(point, rotation, tilt = .18) {
  const x = point[0] * Math.cos(rotation) + point[2] * Math.sin(rotation)
  const z = point[2] * Math.cos(rotation) - point[0] * Math.sin(rotation)
  const y = point[1] * Math.cos(tilt) - z * Math.sin(tilt)
  const depth = point[1] * Math.sin(tilt) + z * Math.cos(tilt)
  return { x, y: -y, depth, visible: depth >= 0 || x * x + y * y > 1.001 }
}
export function greatCircle(start, end, t, lift = .18) {
  const dot = Math.max(-1, Math.min(1, start.reduce((sum, v, i) => sum + v * end[i], 0)))
  const angle = Math.acos(dot)
  let result
  if (angle < 1e-6) result = start.map((v, i) => v * (1 - t) + end[i] * t)
  else if (Math.PI - angle < 1e-6) {
    // Deterministic orthogonal tangent for antipodal endpoints.
    const axis = Math.abs(start[1]) < .9 ? [0, 1, 0] : [1, 0, 0]
    const cross = [start[1] * axis[2] - start[2] * axis[1], start[2] * axis[0] - start[0] * axis[2], start[0] * axis[1] - start[1] * axis[0]]
    const norm = Math.hypot(...cross)
    result = start.map((v, i) => v * Math.cos(Math.PI * t) + cross[i] / norm * Math.sin(Math.PI * t))
  } else result = start.map((v, i) => (v * Math.sin((1 - t) * angle) + end[i] * Math.sin(t * angle)) / Math.sin(angle))
  const scale = 1 + Math.sin(Math.PI * t) * lift
  return result.map(v => v * scale)
}
