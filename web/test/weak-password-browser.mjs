import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_WEAKPWD_PREVIEW_DIST || resolve(web, 'dist'))
const root = resolve(web, '../.tmp/weakpwd-browser')
const fixtures = resolve(process.env.ALINKSEC_WEAKPWD_BROWSER_FIXTURES || resolve(web, '../.tmp/weakpwd-fixtures'))
const stages = Object.fromEntries(['complete','unsupported','partial','late'].map(name => [name,JSON.parse(readFileSync(resolve(fixtures,name+'.json')))]))
assert.ok(existsSync(resolve(dist,'index.html'))); mkdirSync(root,{recursive:true})
const server = createServer((req,res) => {
 let file
 try { file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname)) } catch {res.writeHead(400);res.end();return}
 if(file!==dist && !file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(file) || !statSync(file).isFile())file=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'}[extname(file)] || 'application/octet-stream')
 createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
let stage='complete', fail=false,browser
const errors=[],unexpected=[],checks=[]
try {
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 const context=await browser.newContext({viewport:{width:1440,height:1000}});context.setDefaultTimeout(10000)
 await context.addInitScript(()=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'viewer',role:'viewer'}))})
 await context.route('**/api/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname,current=stages[stage];let data
  if(req.method()!=='GET'){unexpected.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected write'}})}
  if(path==='/api/vuln/scan-coverage') {if(fail)return route.fulfill({status:503,json:{code:503,msg:'检测覆盖暂不可用'}});data=current.coverage}
  else if(path==='/api/vuln/weakpwds')data=current.findings
  else if(['/api/vuln/findings','/api/vuln/ports'].includes(path))data={list:[],total:0}
  else if(path==='/api/vuln/stats')data={}
  else {unexpected.push(path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})}
  return route.fulfill({json:{code:0,data}})
 })
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
 const shot=async name=>page.screenshot({path:root+'/'+name+'.png',fullPage:true,animations:'disabled'})
 await page.goto(`http://127.0.0.1:${server.address().port}/vuln`)
 await page.getByRole('tab',{name:'弱口令',exact:true}).click()
 await expect(page.getByText('有限字典核对完成',{exact:true})).toHaveCount(2)
 await expect(page.getByText('历史风险发现（不代表当前口令状态）')).toBeVisible()
 await expect(page.getByText('命中内置有限字典；口令与哈希均未回传',{exact:true})).toBeVisible()
 assert.ok(!(await page.content()).includes('PUBLIC-SYNTHETIC-SECRET'));await shot('complete-and-redacted-history');checks.push('finite-coverage-and-redacted-history')
 stage='unsupported';await page.getByRole('button',{name:'刷新覆盖'}).click()
 const unsupported=page.getByRole('row').filter({hasText:'未支持 / 未覆盖'});await expect(unsupported).toHaveCount(1);await unsupported.getByRole('button',{name:'详情'}).click()
 let dialog=page.getByRole('dialog',{name:'本地口令检测覆盖'});await expect(dialog).toContainText('该目标的系统或 Agent 不支持');await shot('unsupported-host');await dialog.locator('.el-dialog__headerbtn').click();checks.push('unsupported-target-never-passes')
 stage='partial';await page.getByRole('button',{name:'刷新覆盖'}).click();const partial=page.getByRole('row').filter({hasText:'部分覆盖'});await partial.getByRole('button',{name:'详情'}).click()
 await expect(dialog).toContainText('已达到本次时间或尝试次数上限');await shot('partial-budget');await dialog.locator('.el-dialog__headerbtn').click();checks.push('budget-exhaustion-visible')
 stage='late';await page.getByRole('button',{name:'刷新覆盖'}).click();await page.getByRole('row').filter({hasText:'晚到证据'}).getByRole('button',{name:'详情'}).click()
 await expect(dialog).toContainText('原任务终态保持');await page.setViewportSize({width:390,height:844});const bounds=await dialog.locator('.el-dialog').boundingBox();assert.ok(bounds.x>=0 && bounds.x+bounds.width<=390);await shot('late-evidence-mobile');await dialog.locator('.el-dialog__headerbtn').click();checks.push('late-evidence-and-mobile-dialog')
 fail=true;await page.getByRole('button',{name:'刷新覆盖'}).click();await expect(page.getByText('检测覆盖暂不可用',{exact:true})).toBeVisible();fail=false;await page.getByRole('button',{name:'刷新覆盖'}).click();await expect(page.getByRole('row').filter({hasText:'晚到证据'})).toBeVisible();checks.push('failed-refresh-can-retry')
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,checks,errors,unexpected,mobileDialog:bounds},null,2)+'\n');console.log('Passed weak-password coverage browser checks:',checks)
} finally {await browser?.close();await new Promise(done=>server.close(done))}
