import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {createReadStream,existsSync,mkdirSync,readFileSync,statSync,writeFileSync} from 'node:fs'
import {dirname,extname,resolve,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect as baseExpect} from '@playwright/test'
const expect=baseExpect.configure({timeout:15000})

const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const dist=resolve(process.env.ALINKSEC_ISOLATION_PREVIEW_DIST||resolve(web,'dist'))
const fixture=JSON.parse(readFileSync(resolve(process.env.ALINKSEC_ISOLATION_FIXTURE_DIR||resolve(web,'../.tmp/isolation-console-fixtures'),'console-sqlite.json')))
const artifacts=resolve(web,'../.tmp/isolation-browser')
assert.ok(existsSync(resolve(dist,'index.html')))
mkdirSync(artifacts,{recursive:true})
const server=createServer((req,res)=>{
  let file
  try{file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
  if(file!==dist&&!file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
  if(!existsSync(file)||!statSync(file).isFile())file=resolve(dist,'index.html')
  res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.woff2':'font/woff2'}[extname(file)]||'application/octet-stream')
  createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
let browser,stage='normal'
const errors=[],unexpected=[],writes=[],scenarios=[]
try{
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
  const context=await browser.newContext({viewport:{width:1440,height:1000}})
  context.setDefaultTimeout(10000)
  await context.addInitScript(()=>{
    localStorage.setItem('alinksec_token','isolation-fixture')
    localStorage.setItem('alinksec_user',JSON.stringify({id:1,username:'admin',role:'admin'}))
  })
  await context.route('**/api/**',async route=>{
    const req=route.request(),url=new URL(req.url()),path=url.pathname
    let data
    if(req.method()==='GET'&&path==='/api/hosts'){
      const state=fixture.stages[stage],filter=url.searchParams.get('isolationStatus')
      const list=state.list.filter(h=>filter===null||h.isolation_status===Number(filter))
      data={...state,list,total:list.length}
    }else if(req.method()==='GET'&&path==='/api/hosts/groups') data=[]
    else if(req.method()==='GET'&&path===`/api/hosts/${fixture.agent}`) data=fixture.stages[stage].list.find(h=>h.agent_id===fixture.agent)
    else if(req.method()==='GET'&&new RegExp(`^/api/hosts/${fixture.agent}/(ports|processes|accounts|containers)$`).test(path)) data=[]
    else if(req.method()==='GET'&&path===`/api/hosts/${fixture.agent}/software`) data={list:[],total:0}
    else if(req.method()==='GET'&&path===`/api/hosts/${fixture.agent}/runtime`) data={latest:{},samples:[],serverTime:Date.now(),source:'heartbeat'}
    else if(req.method()==='POST'&&path===`/api/hosts/${fixture.agent}/isolate`){
      writes.push(path);stage='isolating';data={cmdId:'isolate-1',isolationStatus:'isolating'}
    }else if(req.method()==='POST'&&path===`/api/hosts/${fixture.agent}/unisolate`){
      writes.push(path);stage='restoring';data={cmdId:'restore-2',isolationStatus:'restoring'}
    }else{unexpected.push(`${req.method()} ${path}`);return route.fulfill({status:500,json:{code:500,msg:'Unexpected isolation validation request'}})}
    return route.fulfill({json:{code:0,data}})
  })
  const page=await context.newPage()
  page.on('pageerror',error=>errors.push(error.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/hosts`)
  const host=()=>page.locator('.el-table__body-wrapper tr').filter({hasText:'leased'}).first()
  const legacy=page.locator('.el-table__body-wrapper tr').filter({hasText:'旧版主机'}).first()
  await expect(host().getByRole('button',{name:'隔离',exact:true})).toBeVisible()
  await expect(legacy.getByRole('button',{name:'隔离',exact:true})).toHaveCount(0)
  scenarios.push('legacy Agent cannot request unsafe isolation')
  await host().getByRole('button',{name:'隔离',exact:true}).click()
  const dialog=page.getByRole('dialog',{name:'主机隔离确认'})
  await expect(dialog.getByText(/管理通道失联 10 秒后会自动解除隔离/)).toBeVisible()
  await dialog.getByRole('button',{name:'确认隔离',exact:true}).click()
  await expect(host().getByText('隔离中',{exact:true})).toBeVisible()
  stage='isolated'
  await expect(host().getByText('已隔离',{exact:true})).toBeVisible()
  scenarios.push('request stays pending until live authenticated confirmation')
  stage='unknown'
  await expect(host().getByText('隔离状态待确认',{exact:true})).toBeVisible()
  await expect(host().getByText('已自动解除',{exact:true})).toHaveCount(0)
  scenarios.push('missing observations do not claim restored networking')
  stage='restore_failed'
  await expect(host().getByText('解除失败',{exact:true})).toBeVisible()
  stage='restored'
  await expect(host().getByText('已自动解除',{exact:true})).toBeVisible()
  await host().getByRole('button',{name:'详情',exact:true}).click()
  const drawer=page.locator('.el-drawer')
  await expect(drawer.getByText('管理通道未在 10 秒内完成认证确认，已自动恢复网络',{exact:true})).toBeVisible()
  await expect(drawer.getByText('管理通道失联 10 秒后自动解除',{exact:true})).toBeVisible()
  await page.screenshot({path:resolve(artifacts,'automatic-restoration.png'),fullPage:true,animations:'disabled'})
  scenarios.push('confirmed automatic restoration is visible in list and host detail')
  await drawer.locator('.el-drawer__close-btn').click()
  stage='isolated'
  await expect(host().getByText('已隔离',{exact:true})).toBeVisible()
  await page.locator('.el-select').first().click()
  await page.getByRole('option',{name:'已隔离',exact:true}).click()
  await host().getByRole('button',{name:'详情',exact:true}).click()
  await expect(drawer.locator('.detail-identity').getByText('已隔离',{exact:true})).toBeVisible()
  stage='restored'
  await expect(drawer.locator('.detail-identity').getByText('未隔离',{exact:true})).toBeVisible()
  await expect(drawer.getByText('管理通道未在 10 秒内完成认证确认，已自动恢复网络',{exact:true})).toBeVisible()
  scenarios.push('filtered-away host detail receives the fresh restored state')
  await drawer.locator('.el-drawer__close-btn').click()
  stage='isolated'
  await page.goto(`http://127.0.0.1:${server.address().port}/hosts`)
  await expect(host().getByText('已隔离',{exact:true})).toBeVisible()
  await host().getByRole('button',{name:'解除',exact:true}).click()
  await page.getByRole('dialog',{name:'解除隔离确认'}).getByRole('button',{name:'确认解除',exact:true}).click()
  await expect(host().getByText('解除中',{exact:true})).toBeVisible()
  scenarios.push('operator withdrawal remains pending until native cleanup')
  assert.equal(writes.length,2)
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
  writeFileSync(resolve(artifacts,'validation.json'),JSON.stringify({mode:'production web with captured SQLite lifecycle responses',scenarios,errors,unexpected,writes},null,2)+'\n')
  console.log(`Passed host isolation console: ${scenarios.join('; ')}`)
}finally{await browser?.close();await new Promise(done=>server.close(done))}
