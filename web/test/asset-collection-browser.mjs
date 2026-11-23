import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {createServer} from 'node:http'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {resolve,dirname,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'

const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const database=process.env.ALINKSEC_ASSET_DATABASE || 'sqlite'
assert.ok(['sqlite','postgres'].includes(database))
const directory=resolve(process.env.ALINKSEC_ASSET_BROWSER_FIXTURES || resolve(web,'../.tmp/asset-collection-fixtures'))
const bytes=readFileSync(resolve(directory,database,'asset-lifecycle.json')),fixture=JSON.parse(bytes)
assert.equal(fixture.database,database)
assert.equal(fixture.collectorProtobufVerified,true,'Require the actual Go collector protobufs through the real database and REST paths')
const collectorDirectory=resolve(process.env.ALINKSEC_ASSET_COLLECTOR_FIXTURES || resolve(web,'../.tmp/asset-collector-fixtures'))
assert.deepEqual(Object.keys(fixture.collectorSHA256).sort(),['complete','empty','failed'])
for(const [name,digest] of Object.entries(fixture.collectorSHA256))assert.equal(createHash('sha256').update(readFileSync(resolve(collectorDirectory,name+'.pb'))).digest('hex'),digest)
assert.deepEqual(fixture.phases.map(p=>p.name),['complete','failed','partial','unsupported','empty'])
const dist=resolve(process.env.ALINKSEC_ASSET_DIST || resolve(web,'dist'))
const output=resolve(process.env.ALINKSEC_ASSET_BROWSER_ARTIFACTS || resolve(web,'../.tmp/asset-collection-browser',database))
assert.ok(existsSync(resolve(dist,'index.html')));mkdirSync(output,{recursive:true})
const server=createServer((req,res)=>{
 let path
 try{path=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
 if(path!==dist&&!path.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(path)||!statSync(path).isFile())path=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.woff2':'font/woff2'}[extname(path)]||'application/octet-stream')
 createReadStream(path).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
let browser,phase
const errors=[],unexpected=[],checks=[]
const baseline=fixture.phases[0],base='/api/hosts/'+fixture.agentId
const processRow=baseline.responses[base+'/processes'].data[0],port=baseline.responses[base+'/ports'].data[0],disk=baseline.disks[0]
const baselineStates=baseline.responses[base].data.collections
try{
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 const context=await browser.newContext({viewport:{width:1440,height:1050}})
 await context.addInitScript(()=>{
  localStorage.setItem('alinksec_token','fixture')
  localStorage.setItem('alinksec_user',JSON.stringify({username:'viewer',role:'viewer'}))
 })
 await context.route('**/api/**',route=>{
  const request=route.request(),path=new URL(request.url()).pathname
  if(request.method()==='GET'&&Object.hasOwn(phase.responses,path))return route.fulfill({json:phase.responses[path]})
  if(request.method()==='GET'&&path==='/api/metrics/query_range')return route.fulfill({json:{code:0,data:[]}})
  unexpected.push(request.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})
 })
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
 for(phase of fixture.phases){
  const retained=phase.name!=='empty'
  assert.equal(phase.responses[base+'/ports'].data.length,retained?1:0)
  assert.equal(phase.responses[base+'/processes'].data.length,retained?1:0)
  assert.equal(phase.disks.length,retained?1:0)
  assert.deepEqual(phase.responses[base+'/disks'].data,phase.disks)
  await page.goto(`http://127.0.0.1:${server.address().port}/hosts`)
  await page.getByRole('button',{name:'详情',exact:true}).click()
  const drawer=page.locator('.el-drawer')
  const processes=drawer.locator('section').filter({has:page.getByRole('heading',{name:/^本机进程/})})
  const ports=drawer.locator('section').filter({has:page.getByRole('heading',{name:/^监听端口/})})
  const disks=drawer.locator('section').filter({has:page.getByRole('heading',{name:/^磁盘与挂载/})})
  if(retained){
   assert.deepEqual(phase.responses[base+'/ports'].data[0],port)
   assert.deepEqual(phase.responses[base+'/processes'].data[0],processRow)
   assert.deepEqual(phase.disks[0],disk)
   await expect(processes.getByRole('cell',{name:String(processRow.pid),exact:true})).toBeVisible()
   await expect(ports.getByRole('cell',{name:String(port.port),exact:true})).toBeVisible()
   await expect(processes.getByRole('cell',{name:processRow.exe,exact:true})).toBeVisible()
   await expect(disks.getByRole('cell',{name:disk.mount,exact:true})).toBeVisible()
   await expect(drawer.getByText('未采集到本机进程',{exact:true})).toHaveCount(0)
   await expect(drawer.getByText('未发现监听端口',{exact:true})).toHaveCount(0)
  }else{
   await expect(drawer.getByText('完整采集结果中未发现本机进程',{exact:true})).toBeVisible()
   await expect(drawer.getByText('完整采集结果中未发现监听端口',{exact:true})).toBeVisible()
   await expect(drawer.getByText('完整采集结果中未发现磁盘挂载',{exact:true})).toBeVisible()
   await expect(processes.getByRole('cell',{name:String(processRow.pid),exact:true})).toHaveCount(0)
   await expect(ports.getByRole('cell',{name:String(port.port),exact:true})).toHaveCount(0)
  }
  const label={failed:'采集失败，保留上次记录',partial:'采集不完整，保留上次记录',unsupported:'当前系统不支持'}[phase.name]
  if(label)for(const category of ['监听端口','进程','磁盘'])await expect(drawer.getByText(category+'：'+label,{exact:true})).toBeVisible()
  else for(const category of ['监听端口','进程','磁盘'])await expect(drawer.getByText(category+'：最近采集完成',{exact:true})).toBeVisible()
  for(const category of ['ports','processes','disks']) {
   const state=phase.responses[base].data.collections.find(s=>s.category===category)
   const original=baselineStates.find(s=>s.category===category)
   assert.ok(state.received_at>0 && state.succeeded_received_at>0)
   assert.equal(state.succeeded_sequence,phase.name==='empty'?5:1)
   if(phase.name!=='empty')assert.equal(state.succeeded_collected_at,original.succeeded_collected_at)
   const observation=drawer.locator('[data-category="'+category+'"]')
   await observation.locator('summary').click()
   await expect(observation.getByText('最近完整采集：',{exact:false})).toBeVisible()
   await expect(observation).toContainText('最近完整采集：'+new Date(state.succeeded_collected_at).toISOString().replace('T',' ').replace('.000Z',' UTC').replace('Z',' UTC'))
   await observation.locator('summary').click()
  }
  await page.screenshot({path:output+'/'+phase.name+'.png',animations:'disabled'})
  await disks.scrollIntoViewIfNeeded()
  await page.screenshot({path:output+'/'+phase.name+'-disks.png',animations:'disabled'})
  checks.push(phase.name)
 }
 // Explicitly simulated read failure and missing metadata are UI boundaries,
 // distinct from the five captured database lifecycle phases above.
 phase=structuredClone(fixture.phases.at(-1))
 phase.responses[base].data.collections=[]
 await page.reload();await page.getByRole('button',{name:'详情',exact:true}).click()
 await expect(page.locator('.el-drawer').getByText('暂无可用记录；不能据此判断资产为空',{exact:true})).toHaveCount(5)
 checks.push('unknown-coverage-empty')
 delete phase.responses[base+'/disks']
 // This one read error is intentional; all other unexpected requests still fail.
 const expectedFailure=base+'/disks'
 await page.reload();await page.getByRole('button',{name:'详情',exact:true}).click()
 await expect(page.getByText('主机资产加载失败；当前空白不代表主机没有资产',{exact:true})).toBeVisible()
 assert.deepEqual(unexpected.splice(0),['GET '+expectedFailure])
 checks.push('disk-read-failure')
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(output+'/result.json',JSON.stringify({passed:true,database,scope:process.env.ALINKSEC_ASSET_DIST?'page-preview':'production-bundle',source:process.env.GITHUB_SHA||null,run:process.env.GITHUB_RUN_ID||null,
  fixtureSHA256:createHash('sha256').update(bytes).digest('hex'),collectorSHA256:fixture.collectorSHA256,checks,errors,unexpected},null,2)+'\n')
 console.log('Passed database asset collection lifecycle browser:',database,checks)
}finally{await browser?.close();await new Promise(done=>server.close(done))}
