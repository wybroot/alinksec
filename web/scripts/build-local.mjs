// Prebundle large dependencies separately so Rollup can build the application
// with a 256 MiB Node heap on the local acceptance machine.
import { build as vendorBuild } from 'esbuild'
import { build } from 'vite'
import vue from '@vitejs/plugin-vue'
import { mkdir, writeFile, cp } from 'node:fs/promises'
import { resolve } from 'node:path'

process.env.GOMAXPROCS = '1'
const temp = resolve('.tmp/local-build')
const output = resolve('.tmp/local-dist')
const entries = { vue: 'vue', router: 'vue-router', element: 'element-plus', icons: '@element-plus/icons-vue', echarts: 'echarts' }
await mkdir(temp, { recursive: true })
for (const [name, specifier] of Object.entries(entries)) {
  await writeFile(resolve(temp, name + '.js'), `export * from '${specifier}'\n${name === 'element' ? `export { default } from '${specifier}'\n` : ''}`)
}
console.log('Prebundling shared dependencies with one esbuild worker')
await vendorBuild({
  entryPoints: Object.keys(entries).map(name => resolve(temp, name + '.js')),
  outdir: resolve(temp, 'vendor'), bundle: true, splitting: true, platform: 'browser',
  format: 'esm', target: 'es2020', minify: true,
  define: { 'process.env.NODE_ENV': '"production"', __VUE_OPTIONS_API__: 'true', __VUE_PROD_DEVTOOLS__: 'false', __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'false' },
  logLevel: 'info',
})
const external = new Map(Object.entries(entries).map(([name, specifier]) => [specifier, `/vendor/${name}.js`]))
console.log('Building application source with prebundled dependencies')
await build({
  configFile: false, root: process.cwd(),
  plugins: [{ name: 'local-prebundled-dependencies', enforce: 'pre',
    resolveId(id) { if (external.has(id)) return { id: external.get(id), external: true } },
  }, vue()],
  build: { outDir: output, emptyOutDir: true, chunkSizeWarningLimit: 1500 },
})
await cp(resolve(temp, 'vendor'), resolve(output, 'vendor'), { recursive: true })
console.log('Local production bundle ready: ' + output)
