import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const preview = process.env.ALINKSEC_DETECTION_PREVIEW_DIST
const dist = preview ? resolve(preview) : resolve(web, 'dist')
const root = resolve(web, preview ? '../.tmp/detection-capabilities-preview' : '../.tmp/detection-capabilities-browser')
const fixture = JSON.parse(readFileSync(resolve(process.env.ALINKSEC_DETECTION_FIXTURE_DIR || resolve(web, '../.tmp/detection-capabilities-fixtures'), 'console-sqlite.json')))
assert.ok(existsSync(resolve(dist, 'index.html')))
mkdirSync(root, { recursive: true })
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (file !== dist && !file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
let stage='active', reject=true, browser
const errors=[], unexpected=[], writes=[], scenarios=[]
try {
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 const context=await browser.newContext({viewport:{width:1440,height:1000}});context.setDefaultTimeout(8000)
 await context.addInitScript(()=>{if(!localStorage.getItem('alinksec_user')) {localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'admin',role:'admin'}))}})
 await context.route('**/api/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname,method=req.method(),current=fixture.stages[stage]
  let data
  if(method==='GET' && path==='/api/virus/stats') data=current.stats
  else if(method==='GET' && path==='/api/virus/findings') data=current.findings
  else if(method==='GET' && path==='/api/virus/tasks') data=current.tasks
  else if(method==='GET' && path==='/api/virus/db') data=current.db
  else if(method==='GET' && path==='/api/virus/whitelist') data=current.whitelist
  else if(method==='GET' && path===`/api/virus/tasks/${fixture.task}/evidence`) data=current.evidence
  else if(method==='GET' && path===`/api/virus/findings/${fixture.finding}/history`) data=current.history
  else if(method==='POST' && path==='/api/virus/findings/actions') {
   const body=req.postDataJSON();assert.deepEqual(body.findingIds,[fixture.finding]);writes.push({path,body,rejected:reject})
   if(reject) return route.fulfill({status:400,json:{code:400,msg:'处置提交失败，原状态保留'}})
   if(body.action==='quarantine') {stage='pending';data={state:'pending',count:1}}
   else if(body.action==='restore') {stage='restored';data={state:'pending',count:1}}
   else throw new Error('Unexpected action')
  } else if(method==='POST' && path==='/api/virus/realtime') {
   const body=req.postDataJSON();writes.push({path,body});assert.equal(body.enabled,false);assert.equal(body.action,'alert_only');data={state:'policy_committed'}
  } else {unexpected.push(`${method} ${path}`);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})}
  return route.fulfill({json:{code:0,data}})
 })
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
 const row=()=>page.getByRole('row').filter({hasText:'Harmless.Fixture'})
 const reload=async()=>{await page.reload();await expect(row()).toBeVisible()}
 const shot=async name=>page.screenshot({path:root+'/'+name+'.png',fullPage:true,animations:'disabled'})
 await page.goto(`http://127.0.0.1:${server.address().port}/virus`)
 await expect(page.getByRole('heading',{name:'周期病毒检测',exact:true})).toBeVisible()
 await expect(page.getByText('零检出不代表安全。',{exact:false})).toBeVisible()
 await expect(page.getByRole('row').filter({hasText:'Legacy.Allowlist'})).toContainText('旧加白，文件状态未知')
 await row().getByRole('button',{name:'隔离',exact:true}).click();await expect(page.getByText('处置提交失败，原状态保留',{exact:true})).toBeVisible()
 await expect(row()).toContainText('待处置');assert.equal(stage,'active');scenarios.push('failed-submission-keeps-confirmed-state')
 reject=false;await row().getByRole('button',{name:'隔离',exact:true}).click()
 await expect(row()).toContainText('处置待确认');await expect(row()).toContainText('待处置');await expect(row().getByRole('button',{name:'隔离',exact:true})).toHaveCount(0)
 await shot('pending-per-file-receipt');scenarios.push('pending-receipt-never-optimistically-quarantines')
 stage='failed';await reload();await expect(row()).toContainText('处置失败，请查看历史')
 await row().getByRole('button',{name:'处置历史',exact:true}).click()
 let dialog=page.getByRole('dialog',{name:'文件处置历史',exact:true})
 await expect(dialog).toContainText('identity_changed');await expect(dialog).toContainText('首次检出证据');await shot('failed-action-and-initial-evidence')
 await dialog.locator('.el-dialog__headerbtn').click();scenarios.push('failed-receipt-keeps-initial-evidence')
 stage='quarantined';await reload();await expect(row()).toContainText('已隔离');await expect(row()).toContainText('隔离编号：'+'c'.repeat(32));await shot('confirmed-quarantine')
 await row().getByRole('button',{name:'恢复',exact:true}).click();await expect(row()).toContainText('已恢复');scenarios.push('confirmed-quarantine-and-restoration')
 await page.getByRole('tab',{name:'扫描任务',exact:true}).click();await expect(page.getByText('未完整完成',{exact:true})).toBeVisible()
 await page.getByRole('button',{name:'逐主机证据',exact:true}).click();dialog=page.getByRole('dialog',{name:'逐主机扫描证据',exact:true})
 await expect(dialog).toContainText('部分覆盖');await expect(dialog).toContainText('失败 1');await expect(dialog).toContainText('无法读取');await expect(dialog).toContainText('证据摘要');await expect(dialog).toContainText('限定范围完成')
 await shot('partial-and-complete-host-evidence');scenarios.push('partial-scan-and-zero-finding-complete-host-evidence')
 await page.setViewportSize({width:390,height:844});const bounds=await dialog.locator('.el-dialog').boundingBox();assert.ok(bounds.x>=0 && bounds.x+bounds.width<=390);await shot('mobile-host-evidence')
 await dialog.locator('.el-dialog__headerbtn').click();stage='whitelisted';await reload();await expect(row()).toContainText('当前哈希已加白');await expect(row()).toContainText('已恢复')
 await page.getByRole('button',{name:'保存周期策略',exact:true}).click();scenarios.push('whitelist-retains-state-and-periodic-switch-persists')
 await page.evaluate(()=>localStorage.setItem('alinksec_user',JSON.stringify({username:'viewer',role:'viewer'})));await reload()
 for(const name of ['快速扫描','全盘扫描','自定义路径','保存周期策略','批量隔离（0）','批量删除','批量加白','导入特征包','推送全部 Agent']) await expect(page.getByRole('button',{name,exact:true})).toHaveCount(0)
 await row().getByRole('button',{name:'处置历史',exact:true}).click();dialog=page.getByRole('dialog',{name:'文件处置历史',exact:true});await expect(dialog).toContainText('首次检出证据');await shot('viewer-history-mobile')
 await dialog.locator('.evidence-item').filter({hasText:'首次检出证据'}).scrollIntoViewIfNeeded();await expect(dialog.locator('.evidence-item').filter({hasText:'首次检出证据'})).toBeVisible();await shot('viewer-initial-evidence-mobile');scenarios.push('viewer-readonly-history')
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,stages:scenarios,writes,fixture:fixture.task,mobileDialog:bounds,errors,unexpected},null,2)+'\n')
 console.log('Passed detection evidence display: '+scenarios.join(', '))
} finally {await browser?.close();await new Promise(done=>server.close(done))}
