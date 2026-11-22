import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {createHash} from 'node:crypto'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {resolve,dirname,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'

const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const root=resolve(process.env.ALINKSEC_OPERATIONS_FIXTURE || resolve(web,'../.tmp/review-operations/sqlite'))
const captures=JSON.parse(readFileSync(root+'/captures.json','utf8'))
const observations=JSON.parse(readFileSync(root+'/http.json','utf8'))
const dist=resolve(process.env.ALINKSEC_OPERATIONS_PREVIEW_DIST || resolve(web,'dist'))
const output=root+'/browser';mkdirSync(output,{recursive:true})
const sha=value=>createHash('sha256').update(value).digest('hex')
const errors=[],requests=[],checks=[],screenshots=[]
const labels={ready:'已确认就绪',partial:'部分就绪',unknown:'就绪未确认',unsupported:'不支持',disabled:'已停用',offline:'主机离线',stale:'观测过期',stalled:'采集停滞',starting:'启动中',recovering:'恢复中',degraded:'存在降级',failed:'运行失败',unavailable:'引擎不可用',behind:'采集积压'}
const server=createServer((req,res)=>{
 let path=resolve(dist,'.'+new URL(req.url,'http://localhost').pathname)
 if(path!==dist&&!path.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(path)||!statSync(path).isFile())path=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html'}[extname(path)] || 'application/octet-stream');createReadStream(path).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
const base=`http://127.0.0.1:${server.address().port}`
let browser,active,transportFailure=false,hanging=false
const heldRoutes=[]
async function screenshot(page,name){await page.screenshot({path:output+'/'+name+'.png',animations:'disabled'});screenshots.push(name+'.png')}
try {
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 const context=await browser.newContext({viewport:{width:1920,height:1080}})
 const profile=observations.find(row=>row.path==='/api/auth/login').response.data.user
 await context.addInitScript(profile=>{if(location.protocol==='http:'){localStorage.setItem('alinksec_token','sanitized-captured-token');localStorage.setItem('alinksec_user',JSON.stringify(profile))}},profile)
 const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message))
 await page.clock.install()
 await context.route('**/api/**',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname+url.search
  if(transportFailure&&path==='/api/protect/engines'){
   requests.push({capture:active.name,path,method:req.method(),injectedTransportFailure:true});return route.abort('connectionfailed')
  }
  if(hanging&&path==='/api/protect/engines'){
   requests.push({capture:active.name,path,method:req.method(),injectedTransportFailure:true,hung:true});heldRoutes.push(route);return
  }
  const row=active.responses.map(index=>observations[index]).find(row=>row.path===path&&row.method===req.method())
  if(!row){errors.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected acceptance request'}})}
  requests.push({capture:active.name,index:row.index,path,method:req.method(),status:row.status,responseSHA256:sha(JSON.stringify(row.response))})
  await route.fulfill({status:row.status,json:row.response})
 })
 for(const capture of captures){
  active=capture;await page.goto(base+'/screen')
  await expect(page.locator('.clock .date')).toContainText('数据已同步')
  const rows=capture.responses.map(index=>observations[index])
  const engines=rows.find(row=>row.path==='/api/protect/engines').response.data
  await expect(page.locator('[data-engine]')).toHaveCount(9)
  for(const engine of engines){
   const element=page.locator(`[data-engine="${engine.key}"]`)
   await expect(element.locator('.st')).toHaveText(`${labels[engine.status] || labels.unknown} · ${engine.ready}/${engine.total}`)
   assert.equal(await element.locator('.fill').evaluate(node=>node.style.width),engine.coverage+'%')
   assert.equal(await element.locator('.st').evaluate(node=>node.classList.contains('off')),engine.status!=='ready')
  }
  const count=rows.find(row=>row.path==='/api/dashboard/summary').response.data.alerts.automated30d
  await expect(page.locator('[data-confirmed-responses]')).toHaveText(`近 30 日 · 已确认自动响应 ${count} 起`)
  const trend=rows.find(row=>row.path.startsWith('/api/dashboard/screen-trend')).response.data
  await expect(page.getByRole('img')).toHaveAttribute('aria-label',`近7日病毒检出 ${trend.reduce((sum,row)=>sum+Number(row.virus),0)} 起，已确认自动响应 ${trend.reduce((sum,row)=>sum+Number(row.blocked),0)} 起`)
  checks.push(capture.name)
  if(['confirmed-responses','engines-empty','engines-healthy','engines-clamav-failed','engines-file_watch-beyond-page'].includes(capture.name))await screenshot(page,capture.name)
 }
 active=captures.find(capture=>capture.name==='engines-healthy');await page.goto(base+'/screen')
 await expect(page.locator('[data-engine="clamav"] .st')).toContainText('已确认就绪')
 transportFailure=true;await page.clock.fastForward(31_000)
 await expect(page.getByRole('alert')).toContainText('数据更新失败')
 await expect(page.locator('[data-engine="clamav"] .st')).toHaveText('就绪未确认 · 0/2')
 assert.equal(await page.locator('[data-engine="clamav"] .fill').evaluate(node=>node.style.width),'0%')
 await screenshot(page,'api-update-failed');transportFailure=false;await page.clock.fastForward(31_000)
 await expect(page.locator('[data-engine="clamav"] .st')).toHaveText('已确认就绪 · 2/2')
 checks.push('poll-failure-clears-readiness-and-recovery-restores-captured-state')
 hanging=true;await page.clock.fastForward(31_000);await page.clock.fastForward(11_000)
 await expect(page.getByRole('alert')).toContainText('数据更新失败')
 await expect(page.locator('[data-engine="clamav"] .st')).toHaveText('就绪未确认 · 0/2')
 hanging=false;for(const route of heldRoutes)await route.abort('timedout').catch(()=>{})
 await page.clock.fastForward(31_000)
 await expect(page.locator('[data-engine="clamav"] .st')).toHaveText('已确认就绪 · 2/2')
 checks.push('hung-poll-times-out-and-clears-readiness')
 await page.setViewportSize({width:390,height:844});await screenshot(page,'mobile-healthy')
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false)
 assert.deepEqual(errors,[])
 writeFileSync(output+'/result.json',JSON.stringify({passed:true,scope:process.env.ALINKSEC_OPERATIONS_PREVIEW_DIST?'current-source-routed-preview':'production-bundle',
  backendBrowserOverlap:false,capturesSHA256:sha(readFileSync(root+'/captures.json')),httpSHA256:sha(readFileSync(root+'/http.json')),
  checks,requests,errors,screenshots:screenshots.map(name=>({name,sha256:sha(readFileSync(output+'/'+name))})),
  sources:Object.fromEntries(['src/views/Screen.vue','src/api/index.js'].map(name=>[name,sha(readFileSync(web+'/'+name))]))},null,2)+'\n')
} finally {if(browser)await browser.close();await new Promise(done=>server.close(done))}
