import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { chromium, expect } from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..'),dist=resolve(web,'dist'),root=resolve(web,'../.tmp/report-browser'),fixtures=resolve(web,'../.tmp/report-fixtures')
const fixture=JSON.parse(readFileSync(resolve(fixtures,'console-sqlite.json')))
assert.equal(fixture.database,'sqlite');assert.equal(fixture.preview.baseline.pending,3);assert.equal(fixture.preview.baseline.errors,1)
mkdirSync(root,{recursive:true})
const server=createServer((req,res)=>{
  let file;try{file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
  if(!file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
  if(!existsSync(file)||!statSync(file).isFile())file=resolve(dist,'index.html')
  res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.woff2':'font/woff2'}[extname(file)]||'application/octet-stream')
  createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
const base='http://127.0.0.1:'+server.address().port
let pdfPages=0
let browser,role='admin',failPreview=false,failHistory=false,badDigest=false,failSchedule=false,updatedSchedule=false,holdPreview=false,releasePreview,previewStarted=false
const errors=[],unexpected=[],writes=[],checks=[],screenshots=[],downloads=[]
try{
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']})
  const context=await browser.newContext({viewport:{width:1440,height:1100},acceptDownloads:true})
  context.setDefaultTimeout(10000)
  await context.addInitScript(()=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'fixture',role:sessionStorage.getItem('role')||'admin'}))})
  await context.route('**/api/**',async route=>{
    const req=route.request(),url=new URL(req.url()),path=url.pathname,method=req.method()
    const ok=data=>route.fulfill({json:{code:0,data}}),failure=msg=>route.fulfill({status:409,json:{code:40900,msg}})
    if(method==='GET'&&['/api/upgrade/packages','/api/upgrade/versions','/api/notify/channels'].includes(path))return ok([])
    if(method==='GET'&&path==='/api/audit/logs')return ok({total:0,list:[]})
    if(method==='GET'&&path==='/api/hosts/groups')return ok([{id:fixture.group,name:fixture.preview.scope.group}])
    if(method==='GET'&&path==='/api/reports/preview'){
      assert.equal(url.searchParams.get('from'),fixture.preview.query.from);assert.equal(url.searchParams.get('to'),fixture.preview.query.to);assert.equal(Number(url.searchParams.get('groupId')),fixture.group)
      if(holdPreview){previewStarted=true;await new Promise(done=>{releasePreview=done})}
      if(failPreview)return failure('报表数据暂不可用')
      return ok(fixture.preview)
    }
    if(method==='GET'&&path==='/api/reports/snapshots')return failHistory?failure('历史列表暂不可用'):ok(fixture.history)
    if(method==='GET'&&path==='/api/reports/snapshots/'+fixture.snapshot.id)return ok(fixture.snapshot)
    if(method==='POST'&&path==='/api/reports/snapshots'){
      assert.ok(['admin','operator'].includes(role));const data=req.postDataJSON();assert.equal(data.from,fixture.preview.query.from);assert.equal(data.to,fixture.preview.query.to);assert.equal(data.groupId,fixture.group);assert.ok(data.title);assert.equal(data.created_by,undefined);writes.push({operation:'snapshot',body:data});return ok(fixture.snapshot)
    }
    if(method==='GET'&&path==='/api/reports/schedules')return ok(updatedSchedule?[fixture.updatedSchedule]:fixture.schedules)
    if(method==='PUT'&&path==='/api/reports/schedules/'+fixture.schedule.id){
      assert.equal(role,'admin');const data=req.postDataJSON();assert.equal(data.revision,fixture.schedule.revision);assert.equal(data.title,fixture.updatedSchedule.title)
      if(failSchedule)return failure('计划已变化，请刷新后重试')
      writes.push({operation:'schedule',body:data});updatedSchedule=true;return ok(fixture.updatedSchedule)
    }
    if(method==='GET'&&path.startsWith('/api/reports/compliance.')){
      assert.equal(url.searchParams.get('expectedDataDigest'),fixture.preview.dataDigest);return failure('报表数据已变化，请刷新预览或查看已保存的快照')
    }
    const exportMatch=path.match(/^\/api\/reports\/snapshots\/([^/]+)\/export\.(csv|xlsx|html|json)$/)
    if(method==='GET'&&exportMatch){
      assert.equal(exportMatch[1],fixture.snapshot.id);const format=exportMatch[2],bytes=readFileSync(resolve(fixtures,'report-sqlite.'+format))
      const types={csv:'text/csv;charset=UTF-8',xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',html:'text/html;charset=UTF-8',json:'application/json'}
      return route.fulfill({body:bytes,headers:{'Content-Type':types[format],'X-Content-SHA256':badDigest?'0'.repeat(64):createHash('sha256').update(bytes).digest('hex'),'X-Report-Snapshot-SHA256':fixture.snapshot.sha256,'Cache-Control':'no-store'}})
    }
    unexpected.push(method+' '+path);return route.fulfill({status:500,json:{code:50000,msg:'Unexpected request'}})
  })
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message))
  const panel=page.locator('.report-panel'),document=page.locator('.report-document')
  const shot=async name=>{await expect(page.locator('.el-loading-mask:visible')).toHaveCount(0);await page.screenshot({path:resolve(root,name),animations:'disabled'});screenshots.push(name)}
  const openSystem=async()=>{await page.goto(base+'/system');await page.getByRole('tab',{name:'合规报表',exact:true}).click();await expect(panel.locator('.report-history')).toContainText(fixture.snapshot.title)}
  const openSnapshot=async()=>{await panel.locator('.report-history').getByRole('button',{name:'查看',exact:true}).click();await expect(document).toContainText(fixture.snapshot.sha256)}
  await openSystem();await openSnapshot()
  await expect(document).toContainText('14.3%');await expect(document).toContainText('危急（5）');await expect(document).toContainText('待回报');await expect(document).toContainText('<img src=x onerror=alert(1)>');await expect(document.locator('img')).toHaveCount(0)
  await document.scrollIntoViewIfNeeded();await page.evaluate(()=>window.scrollTo(0,0));await shot('report-desktop.png');checks.push('database_snapshot_counts_unknowns_and_text_only_markup')
  for(const format of ['csv','xlsx','html','json']){
    const label={csv:'导出 CSV',xlsx:'导出 Excel',html:'打印版 HTML',json:'导出 JSON'}[format],pending=page.waitForEvent('download')
    await panel.getByRole('button',{name:label,exact:true}).click();const file=await pending;const path=resolve(root,'download.'+format);await file.saveAs(path);assert.deepEqual(readFileSync(path),readFileSync(resolve(fixtures,'report-sqlite.'+format)));downloads.push({format,sha256:createHash('sha256').update(readFileSync(path)).digest('hex')})
  }
  badDigest=true;await panel.getByRole('button',{name:'导出 CSV',exact:true}).click();await expect(panel).toContainText('报表文件摘要不匹配');badDigest=false;checks.push('four_authenticated_formats_and_digest_rejection')
  await page.emulateMedia({media:'print'});assert.equal(await panel.locator('.report-history').evaluate(el=>getComputedStyle(el).display),'none');assert.equal(await panel.locator('.report-controls').evaluate(el=>getComputedStyle(el).display),'none');assert.equal(await page.locator('body').evaluate(el=>getComputedStyle(el).backgroundColor),'rgb(255, 255, 255)')
  await page.pdf({path:resolve(root,'report-production.pdf'),format:'A4',landscape:true,printBackground:true})
  const pdf=readFileSync(resolve(root,'report-production.pdf'));assert.equal(pdf.subarray(0,5).toString(),'%PDF-')
  const info=execFileSync('pdfinfo',[resolve(root,'report-production.pdf')],{encoding:'utf8'});writeFileSync(resolve(root,'report-production-info.txt'),info);pdfPages=Number(info.match(/^Pages:\s+(\d+)/m)?.[1]);assert.ok(pdfPages>0&&pdfPages<100)
  for(const [name,number] of [['report-pdf-first',1],['report-pdf-last',pdfPages]])execFileSync('pdftoppm',['-f',String(number),'-l',String(number),'-singlefile','-scale-to','1600','-png',resolve(root,'report-production.pdf'),resolve(root,name)])
  execFileSync('pdftotext',['-layout',resolve(root,'report-production.pdf'),resolve(root,'report-production.txt')]);const printed=readFileSync(resolve(root,'report-production.txt'),'utf8')
  assert.ok(printed.includes(fixture.snapshot.title));assert.ok(printed.includes('待回报'));assert.ok(printed.includes('不代表等保认证结论'));assert.ok(!printed.includes('新增报表计划'));assert.ok(!printed.includes('刷新历史'));await page.emulateMedia({media:'screen'});checks.push('actual_production_pdf_contains_report_and_excludes_controls')
  const plan=panel.locator('.report-plans');await plan.getByRole('button',{name:'编辑',exact:true}).click();const dialog=page.getByRole('dialog',{name:'定时报表计划',exact:true})
  await dialog.getByRole('textbox').first().fill(fixture.updatedSchedule.title);failSchedule=true;await dialog.getByRole('button',{name:'保存计划',exact:true}).click();await expect(dialog).toContainText('计划已变化，请刷新后重试');failSchedule=false
  await dialog.getByRole('button',{name:'保存计划',exact:true}).click();await expect(dialog).not.toBeVisible();await expect(plan).toContainText(fixture.updatedSchedule.title)
  await panel.locator('.report-history').scrollIntoViewIfNeeded();await shot('report-history-desktop.png');checks.push('administrator_schedule_revision_and_visible_failure')
  await panel.getByPlaceholder('开始日',{exact:true}).fill(fixture.preview.query.from);await panel.getByPlaceholder('结束日',{exact:true}).fill(fixture.preview.query.to);await panel.getByPlaceholder('结束日',{exact:true}).press('Enter')
  await panel.locator('.report-toolbar>.el-select').first().locator('.el-select__wrapper').click();await page.getByRole('option',{name:fixture.preview.scope.group,exact:true}).click();await expect(document).toHaveCount(0)
  await panel.getByRole('button',{name:'生成预览',exact:true}).click();await expect(document).toContainText('ALinkSec 安全运营报表')
  await panel.getByRole('button',{name:'导出 CSV',exact:true}).click();await expect(panel).toContainText('报表数据已变化，请刷新预览或查看已保存的快照');checks.push('natural_day_scope_and_changed_preview_export_rejected')
  await panel.getByRole('textbox',{name:'快照名称',exact:true}).fill('客户安全运营周报');await panel.getByRole('button',{name:'保存当前统计快照',exact:true}).click();await expect(document).toContainText(fixture.snapshot.sha256);checks.push('operator_or_administrator_save_uses_normalized_query')
  for(const selectedRole of ['operator','viewer']){
    role=selectedRole;await page.evaluate(value=>sessionStorage.setItem('role',value),role);await openSystem();await openSnapshot();await expect(panel.getByRole('button',{name:'新增报表计划',exact:true})).toHaveCount(0)
    await expect(panel.getByRole('button',{name:'保存当前统计快照',exact:true})).toHaveCount(role==='viewer'?0:1)
    await expect(panel.locator('.report-plans').getByRole('button',{name:'编辑',exact:true})).toHaveCount(0)
  }
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>window.scrollTo(0,0));assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=391));await shot('report-mobile.png');checks.push('viewer_and_operator_permissions_and_mobile_layout')
  await page.setViewportSize({width:1440,height:1100});await page.evaluate(()=>sessionStorage.setItem('role','admin'));role='admin';await openSystem()
  await panel.getByPlaceholder('开始日',{exact:true}).fill(fixture.preview.query.from);await panel.getByPlaceholder('结束日',{exact:true}).fill(fixture.preview.query.to);await panel.getByPlaceholder('结束日',{exact:true}).press('Enter')
  await panel.locator('.report-toolbar>.el-select').first().locator('.el-select__wrapper').click();await page.getByRole('option',{name:fixture.preview.scope.group,exact:true}).click()
  failPreview=true;await panel.getByRole('button',{name:'生成预览',exact:true}).click();await expect(panel).toContainText('报表数据暂不可用');await expect(document).toHaveCount(0);await expect(panel.getByRole('button',{name:'导出 CSV',exact:true})).toBeDisabled()
  failHistory=true;await panel.getByRole('button',{name:'刷新历史',exact:true}).click();await expect(panel.locator('.report-history')).toContainText('历史列表暂不可用');await expect(panel.locator('.report-history')).not.toContainText(fixture.snapshot.title)
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>window.scrollTo(0,0));await shot('report-error-mobile.png');checks.push('failed_preview_and_history_clear_stale_content')
  failPreview=false;holdPreview=true;await panel.getByRole('button',{name:'生成预览',exact:true}).click();await expect.poll(()=>previewStarted).toBe(true);await page.goto(base+'/login');releasePreview();await page.waitForTimeout(150);await expect(page.locator('.report-document')).toHaveCount(0);checks.push('unmounted_late_preview_cannot_restore_report')
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
}finally{
  writeFileSync(resolve(root,'result.json'),JSON.stringify({passed:checks.length===9&&errors.length===0&&unexpected.length===0,checks,errors,unexpected,writes,screenshots,downloads,pdfPages},null,2)+'\n')
  if(browser)await browser.close();await new Promise(done=>server.close(done))
}
console.log('Production reporting browser: nine scenario groups passed')
