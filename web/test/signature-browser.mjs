import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {createServer} from 'node:http'
import {dirname,resolve,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const dist=resolve(process.env.ALINKSEC_SIGNATURE_PREVIEW_DIST||resolve(web,'dist'))
const fixtures=resolve(process.env.ALINKSEC_SIGNATURE_FIXTURE_DIR||resolve(web,'../.tmp/signature-fixtures'))
const root=resolve(web,'../.tmp/signature-browser');mkdirSync(root,{recursive:true})
const stages=Object.fromEntries(['status','full-only'].map(n=>[n,JSON.parse(readFileSync(resolve(fixtures,n+'.json')))]))
assert.ok(existsSync(resolve(dist,'index.html')))
const server=createServer((req,res)=>{
  let file
  try{file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
  if(file!==dist&&!file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
  if(!existsSync(file)||!statSync(file).isFile())file=resolve(dist,'index.html')
  res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'}[extname(file)]||'application/octet-stream')
  createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
let browser,page,stage='status',fail=false
const checks=[],errors=[],unexpected=[]
try{
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
  const context=await browser.newContext({viewport:{width:1440,height:1000}});context.setDefaultTimeout(8000)
  await context.addInitScript(()=>{if(!localStorage.getItem('alinksec_user')){localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'operator',role:'operator'}))}})
  await context.route('**/api/**',async route=>{
    const req=route.request(),path=new URL(req.url()).pathname
    if(path==='/api/libraries'&&req.method()==='GET')return fail?route.fulfill({status:503,json:{code:503,msg:'安全库状态暂不可用'}}):route.fulfill({json:{code:0,data:stages[stage]}})
    unexpected.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})
  })
  page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto('http://127.0.0.1:'+server.address().port+'/libraries')
  const panel=page.locator('.panel').first()
  await expect(panel.getByText(stages.status.signature.db_version,{exact:true})).toBeVisible()
  await expect(panel.getByText(new RegExp('增量 .*基于 '+stages.status.signature.delta_base_version))).toBeVisible()
  await expect(panel.getByText(/差量失败时回退完整包/)).toBeVisible();checks.push('captured-release-full-and-delta-sizes-and-base')
  await page.screenshot({path:root+'/delta-desktop.png',fullPage:true,animations:'disabled'})
  stage='full-only';await panel.getByRole('button',{name:'刷新',exact:true}).click();await expect(panel.getByText(/当前版本使用全量更新/)).toBeVisible();checks.push('full-only-release-without-false-delta')
  fail=true;await panel.getByRole('button',{name:'刷新',exact:true}).click();await expect(panel.getByText('安全库状态暂不可用',{exact:true})).toBeVisible();await expect(panel.getByText(stages['full-only'].signature.db_version,{exact:true})).toHaveCount(0);await expect(panel.getByText(/当前有效病毒特征为空/)).toHaveCount(0);checks.push('failed-load-hides-old-release-and-does-not-claim-empty-library')
  fail=false;stage='status';await panel.getByRole('button',{name:'刷新',exact:true}).click();await expect(panel.getByText(stages.status.signature.db_version,{exact:true})).toBeVisible();checks.push('status-retry-recovers')
  await page.setViewportSize({width:390,height:844});await expect(panel.getByText(new RegExp('增量 .*基于 '+stages.status.signature.delta_base_version))).toBeVisible()
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile page overflow')
  await page.screenshot({path:root+'/delta-mobile.png',fullPage:true,animations:'disabled'});checks.push('mobile-update-details-fit-viewport')
  await page.evaluate(()=>localStorage.setItem('alinksec_user',JSON.stringify({username:'viewer',role:'viewer'})));await page.reload();await expect(panel.getByText(stages.status.signature.db_version,{exact:true})).toBeVisible();await expect(panel.getByRole('button',{name:'导入病毒特征库',exact:true})).toHaveCount(0);checks.push('viewer-can-read-update-metadata-without-import-controls')
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
  writeFileSync(root+'/result.json',JSON.stringify({passed:true,checks,errors,unexpected,release:stages.status.signature}));console.log('PASS signature update metadata, fallback explanations, retry, roles and mobile layouts')
}catch(error){writeFileSync(root+'/result.json',JSON.stringify({passed:false,error:error.message,checks,errors,unexpected}));await page?.screenshot({path:root+'/failure.png',fullPage:true,timeout:3000}).catch(()=>{});throw error}
finally{await browser?.close();await new Promise(done=>server.close(done))}
