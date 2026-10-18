import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_WINDOWS_LOGIN_PREVIEW_DIST || resolve(web, 'dist'))
const root = resolve(web, '../.tmp/windows-login-browser')
const fixtures = resolve(process.env.ALINKSEC_WINDOWS_LOGIN_BROWSER_FIXTURES || resolve(web, '../.tmp/windows-login-fixtures'))
const stages = Object.fromEntries(['coverage','unsupported','rules'].map(name => [name,JSON.parse(readFileSync(resolve(fixtures,name+'.json')))]))
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
let stage='coverage', fail=false, failSave=false, browser
const errors=[], unexpected=[], checks=[], writes=[]
try {
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 async function session(role) {
  const context=await browser.newContext({viewport:{width:1440,height:1050}});context.setDefaultTimeout(10000)
  await context.addInitScript(role=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:role,role}))},role)
  await context.route('**/api/**',async route=>{
   const req=route.request(),path=new URL(req.url()).pathname;let data
   if(req.method()==='PUT' && path==='/api/protect/rules/PR-0004' && role==='operator') {
    const body=req.postDataJSON();writes.push(body)
    if(failSave)return route.fulfill({status:503,json:{code:503,msg:'保存暂不可用'}})
    return route.fulfill({json:{code:0,data:null}})
   }
   if(req.method()!=='GET'){unexpected.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected write'}})}
   if(path==='/api/protect/windows-login-status'){if(fail)return route.fulfill({status:503,json:{code:503,msg:'监测状态暂不可用'}});data=stages[stage].status}
   else if(path==='/api/protect/rules')data=stages.rules.rules
   else if(path==='/api/protect/engines')data=[]
   else if(path==='/api/protect/blocks')data=[]
   else {unexpected.push(path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})}
   return route.fulfill({json:{code:0,data}})
  })
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(`http://127.0.0.1:${server.address().port}/protect`)
  return {page,context,section:page.getByTestId('windows-login')}
 }
 let {page,context,section}=await session('viewer')
 await expect(section.getByText('正在监测',{exact:true})).toBeVisible();await expect(section.getByText('无法读取 Security 日志',{exact:true})).toBeVisible()
 await expect(section.getByRole('button',{name:'保存 Windows 登录配置'})).toBeDisabled()
 await page.setViewportSize({width:1440,height:1800});await section.scrollIntoViewIfNeeded();await page.screenshot({path:root+'/coverage-desktop.png',fullPage:true,animations:'disabled'});checks.push('per-host-coverage-and-viewer-readonly')
 stage='unsupported';await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('Agent 不支持',{exact:true})).toBeVisible();await expect(section.getByText('主机离线或禁用',{exact:true})).toBeVisible();await expect(section.getByText('正在监测',{exact:true})).toHaveCount(0);checks.push('old-offline-agents-never-appear-active')
 fail=true;await section.getByRole('button',{name:'刷新状态'}).click();await expect(section.getByText('监测状态暂不可用',{exact:true})).toBeVisible();fail=false;await section.getByRole('button',{name:'重试',exact:true}).click();await expect(section.getByText('Agent 不支持',{exact:true})).toBeVisible();checks.push('failed-status-refresh-can-retry')
 await context.close();await browser.close();browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']});stage='coverage';({page,context,section}=await session('operator'))
 await expect(section.getByRole('button',{name:'保存 Windows 登录配置'})).toBeEnabled()
 await section.getByPlaceholder('3389，按需增加 445').fill('43389, 43445')
 await section.locator('.el-switch').first().click();await section.getByText('限时封禁来源',{exact:true}).click()
 failSave=true;await section.getByRole('button',{name:'保存 Windows 登录配置'}).click();await expect(section.getByRole('alert').filter({hasText:'保存暂不可用'})).toBeVisible()
 failSave=false;await section.getByRole('button',{name:'保存 Windows 登录配置'}).click();await expect(section.getByRole('status')).toContainText('实际生效情况')
 assert.equal(writes.length,2);const body=writes[1];assert.equal(body.enabled,true);assert.deepEqual(body.actions,['alert','block_ip']);assert.deepEqual(body.match.windows_ports,[43389,43445]);assert.deepEqual(body.match.windows_logon_types,[3,10]);assert.deepEqual(body.match.platforms,['windows']);assert.equal(body.match.windows_contract,1);assert.equal(body.match.ssh_ports,undefined)
 checks.push('operator-explicit-scope-save-and-failed-save-retry')
 await page.setViewportSize({width:390,height:844});await section.scrollIntoViewIfNeeded();const bounds=await section.boundingBox();assert.ok(bounds.x>=0&&bounds.x+bounds.width<=391);await page.screenshot({path:root+'/settings-mobile.png',fullPage:true,animations:'disabled'});await section.getByText('Windows 主机监测状态',{exact:true}).scrollIntoViewIfNeeded();await page.screenshot({path:root+'/status-mobile.png',animations:'disabled'});checks.push('mobile-settings-fit-viewport')
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,checks,errors,unexpected,mobileSection:bounds},null,2)+'\n');console.log('Passed Windows login browser checks:',checks)
} finally {await browser?.close();await new Promise(done=>server.close(done))}
