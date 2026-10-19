import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const dist=resolve(process.env.ALINKSEC_FILE_WATCH_PREVIEW_DIST || resolve(web,'dist'))
const root=resolve(web,'../.tmp/file-watch-browser')
const fixtures=resolve(process.env.ALINKSEC_FILE_WATCH_BROWSER_FIXTURES || resolve(web,'../.tmp/file-watch-fixtures'))
const stages=Object.fromEntries(['coverage','recovering','stalled','unsupported'].map(n=>[n,JSON.parse(readFileSync(resolve(fixtures,n+'.json')))]))
mkdirSync(root,{recursive:true});assert.ok(existsSync(resolve(dist,'index.html')))
const server = createServer((req,res) => {
 let file
 try { file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname)) } catch {res.writeHead(400);res.end();return}
 if(file!==dist && !file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(file) || !statSync(file).isFile())file=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'}[extname(file)] || 'application/octet-stream')
 createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
let stage='coverage',fail=false,browser,page
const checks=[],errors=[],unexpected=[]
try {
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 const context=await browser.newContext({viewport:{width:1440,height:1050}})
 await context.addInitScript(()=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'viewer',role:'viewer'}))})
 await context.route('**/api/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname
  if(req.method()!=='GET'){unexpected.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected write'}})}
  let data
  if(path==='/api/protect/file-watch-status'){
   if(fail)return route.fulfill({status:503,json:{code:503,msg:'文件监控状态暂不可用'}})
   data=stages[stage]
  } else if(path==='/api/protect/windows-login-status')data={items:[],total:0}
  else if(['/api/protect/rules','/api/protect/engines','/api/protect/blocks'].includes(path))data=[]
  else {unexpected.push(path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})}
  return route.fulfill({json:{code:0,data}})
 })
 page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(`http://127.0.0.1:${server.address().port}/protect`)
 const section=page.getByTestId('file-watch')
 await expect(section.getByText('正在监听',{exact:true})).toBeVisible();await expect(section.getByText('覆盖降级',{exact:true})).toBeVisible();await expect(section.getByText('系统事件丢失或读取失败，已请求补查',{exact:true})).toBeVisible()
 await section.scrollIntoViewIfNeeded();await expect(section.locator('.el-loading-mask')).toHaveCount(0);await section.screenshot({path:root+'/coverage-desktop.png',animations:'disabled'});checks.push('native-and-degraded-coverage-from-database')
 stage='recovering';await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('正在补查',{exact:true})).toBeVisible();checks.push('recovery-never-appears-complete')
 stage='stalled';await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('监听状态未推进',{exact:true})).toBeVisible();checks.push('stalled-heartbeat-not-active')
 stage='unsupported';await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('Agent 不支持',{exact:true})).toBeVisible();await expect(section.getByText('主机离线或禁用',{exact:true})).toBeVisible();await expect(section.getByText('正在监听',{exact:true})).toHaveCount(0);checks.push('old-and-offline-agents-explicit')
 fail=true;await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('文件监控状态暂不可用',{exact:true})).toBeVisible();fail=false;await section.getByRole('button',{name:'重试',exact:true}).click();await expect(section.getByText('Agent 不支持',{exact:true})).toBeVisible();checks.push('failed-refresh-hides-old-state-and-retries')
 stage='coverage';await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('正在监听',{exact:true})).toBeVisible()
 await page.setViewportSize({width:390,height:844});await section.scrollIntoViewIfNeeded();const bounds=await section.boundingBox();assert.ok(bounds.x>=0&&bounds.x+bounds.width<=391);await page.screenshot({path:root+'/coverage-mobile.png',animations:'disabled'});checks.push('mobile-coverage-fits-viewport')
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,checks,errors,unexpected,mobileSection:bounds},null,2)+'\n');console.log('Passed file event browser checks:',checks)
} catch(e) {if(page)await page.screenshot({path:root+'/failure.png',fullPage:true}).catch(()=>{});writeFileSync(root+'/failure.json',JSON.stringify({error:String(e),checks,errors,unexpected},null,2));throw e}
finally {await browser?.close();await new Promise(done=>server.close(done))}
