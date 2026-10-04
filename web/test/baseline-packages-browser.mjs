import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {createServer} from 'node:http'
import {dirname,resolve,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const preview=process.env.ALINKSEC_BASELINE_PREVIEW_DIST
const dist=preview ? resolve(preview) : resolve(web,'dist')
const root=resolve(web,preview ? '../.tmp/baseline-preview-artifacts' : '../.tmp/baseline-browser-artifacts')
const mode=`${preview ? 'page preview' : 'production web bundle'}; captured SQLite API responses; completed reports are protocol fixtures`
assert.ok(existsSync(resolve(dist,'index.html')),'Build the selected web bundle before this check')
mkdirSync(root,{recursive:true})
const fixtures=JSON.parse(readFileSync(resolve(web,'../.tmp/baseline-browser-fixtures-sqlite.json')))
assert.equal(fixtures.mode,'sqlite')
const mime={'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.woff2':'font/woff2'}
const server=createServer((req,res)=>{
  let file
  try{file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
  if(file!==dist&&!file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
  if(!existsSync(file)||!statSync(file).isFile())file=resolve(dist,'index.html')
  res.setHeader('Content-Type',mime[extname(file)]||'application/octet-stream')
  createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(r=>server.listen(0,'127.0.0.1',r))
const baseURL='http://127.0.0.1:'+server.address().port
const errors=[],writes=[],unexpected=[]
let browser,page,rejectReview=true,completeTests=false,rejectCoverage=true
const ids=Object.fromEntries(Object.entries(fixtures.platforms).map(([platform,stages])=>[stages.candidate.id,platform]))
const details=Object.fromEntries(Object.values(fixtures.platforms).map(stages=>[stages.candidate.id,structuredClone(stages.candidate)]))
const summary=(doc)=>({...fixtures.list.find(pkg=>pkg.id===doc.id),status:doc.status,template_id:doc.template_id,test_task_id:doc.test_task_id})
process.once('SIGTERM',async()=>{await browser?.close();process.exit(1)})
try {
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
  const context=await browser.newContext({viewport:{width:1440,height:1000},baseURL})
  context.setDefaultTimeout(8000)
  await context.addInitScript(()=>{if(!localStorage.getItem('alinksec_token')){localStorage.setItem('alinksec_token','browser-fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'admin',role:'admin'}))}})
  await context.route('**/api/**',async route=>{
    const request=route.request(),url=new URL(request.url()),path=url.pathname,method=request.method()
    const ok=data=>route.fulfill({json:{code:0,data}})
    if(path==='/api/baseline/packages'&&method==='GET')return ok(Object.values(details).map(summary))
    if(path==='/api/baseline/templates')return ok(fixtures.templates.map(template=>({...template,enabled:template.package_id?details[template.package_id]?.status==='published':template.enabled})))
    if(path==='/api/hosts')return ok(url.searchParams.get('page')==='2'?fixtures.hostsPage2:fixtures.hosts)
    if(path==='/api/baseline/latest')return ok({list:[],total:0})
    if(path==='/api/baseline/coverage'){
      writes.push({path,body:request.postDataJSON()})
      return ok(fixtures.coverage.map(row=>({...row,covered:rejectCoverage&&Number(row.os_type)===2?false:row.covered})))
    }
    if(path==='/api/baseline/tasks'&&method==='POST'){writes.push({path,body:request.postDataJSON()});return ok({taskId:999})}
    if(path==='/api/baseline/packages/import'){
      assert.ok(request.headers()['content-type'].startsWith('multipart/form-data;'))
      writes.push({path});return ok(fixtures.platforms.linux.candidate)
    }
    const match=path.match(/^\/api\/baseline\/packages\/([^/]+)(?:\/(review|test|publish|withdraw))?$/)
    if(match&&ids[match[1]]){
      const id=match[1],operation=match[2],stages=fixtures.platforms[ids[id]]
      if(method==='GET'){
        if(completeTests&&details[id].status==='approved'&&details[id].test_task_id)details[id]=structuredClone(stages.completed)
        return ok(details[id])
      }
      const body=request.postDataJSON()
      if(operation==='review'&&rejectReview)return route.fulfill({status:400,json:{code:40000,msg:'审核保存失败，请重试'}})
      writes.push({path,body})
      const next={review:stages.approved,test:stages.testing,publish:stages.published,withdraw:stages.withdrawn}[operation]
      if(next){details[id]=structuredClone(next);return ok(details[id])}
    }
    unexpected.push(`${method} ${path}`)
    return route.fulfill({status:500,json:{code:50000,msg:'Unexpected API request'}})
  })
  page=await context.newPage();page.on('pageerror',error=>errors.push(error.message))
  await page.goto('/baseline-templates')
  await expect(page.getByRole('heading',{name:'基线模板',exact:true})).toBeVisible()
  await expect(page.getByRole('cell',{name:'Windows 基础安全核查',exact:true})).toBeVisible()
  await expect(page.getByRole('cell',{name:'Linux 基础安全核查',exact:true})).toBeVisible()
  await page.locator('input[type=file]').setInputFiles({name:'baseline.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(fixtures.platforms.linux.candidate.document))})
  await page.getByRole('button',{name:'导入候选版本',exact:true}).click()
  const dialog=page.getByRole('dialog',{name:'基线模板版本',exact:true})
  await expect(dialog.getByRole('heading',{name:/Linux 基础安全核查/})).toBeVisible()
  await expect(dialog.getByText('来源与适用范围变更',{exact:true})).toBeVisible()
  await dialog.getByRole('button',{name:'审核通过',exact:true}).click()
  assert.equal(writes.filter(write=>write.path.endsWith('/review')).length,0,'A review requires an explicit note')
  await dialog.getByRole('textbox',{name:'审核说明',exact:true}).fill('Reviewed source, applicability and unsupported rules')
  await dialog.getByRole('button',{name:'审核通过',exact:true}).click()
  await expect(page.getByText('审核保存失败，请重试',{exact:true})).toBeVisible()
  await expect(dialog.getByRole('button',{name:'审核通过',exact:true})).toBeVisible()
  await expect(dialog.getByRole('textbox',{name:'审核说明',exact:true})).toHaveValue('Reviewed source, applicability and unsupported rules')
  rejectReview=false
  await dialog.getByRole('button',{name:'审核通过',exact:true}).click()
  await expect(dialog.getByRole('button',{name:'发布为可选模板',exact:true})).toBeDisabled()
  assert.equal(writes.filter(write=>write.path.endsWith('/test')).length,0,'Approval must not run a check')
  const target=fixtures.platforms.linux.approved.testTargets.find(host=>host.agent_id==='ci-smoke-001')
  await dialog.locator('.actions .el-select').click()
  await page.getByRole('option',{name:`${target.hostname} · ${target.os_version||'Linux'}`,exact:true}).click()
  await dialog.getByRole('heading').first().click()
  await dialog.getByRole('button',{name:'下发测试核查',exact:true}).click()
  await expect(dialog.getByRole('heading',{name:/测试核查/})).toBeVisible()
  await expect(dialog.getByRole('button',{name:'发布为可选模板',exact:true})).toBeDisabled()
  assert.deepEqual(writes.find(write=>write.path.endsWith('/test')).body,{agentIds:['ci-smoke-001']})
  completeTests=true
  await dialog.getByRole('button',{name:'刷新版本',exact:true}).click()
  await expect(dialog.getByRole('button',{name:'发布为可选模板',exact:true})).toBeEnabled()
  await dialog.getByRole('textbox',{name:'审核说明',exact:true}).fill('Complete test results reviewed; noncompliant findings require separate treatment')
  await dialog.getByRole('button',{name:'发布为可选模板',exact:true}).click()
  await expect(dialog.getByRole('heading',{name:/已发布/})).toBeVisible()
  await dialog.getByRole('textbox',{name:'审核说明',exact:true}).fill('Withdraw the superseded candidate')
  await dialog.getByRole('button',{name:'撤回版本',exact:true}).click()
  await expect(dialog.getByRole('heading',{name:/已撤回/})).toBeVisible()
  await expect(dialog.getByRole('button',{name:'下发测试核查',exact:true})).toHaveCount(0)
  await dialog.getByRole('button',{name:'关闭',exact:true}).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.locator('.el-message')).toHaveCount(0)
  await page.screenshot({path:root+'/templates-desktop.png',fullPage:true,animations:'disabled'})

  // The task form sends an empty selection for server-side OS matching and blocks uncovered hosts.
  await page.goto('/baseline')
  await page.getByRole('button',{name:'+ 发起核查',exact:true}).click()
  const create=page.getByRole('dialog',{name:'发起基线核查',exact:true})
  await expect(create.getByText('按 Agent 系统自动选择',{exact:true})).toBeVisible()
  const hosts=create.getByRole('combobox').last()
  await hosts.click()
  for(const name of ['ci-smoke-host-001','ci-windows-test-host'])await page.getByRole('option').filter({hasText:name}).click()
  await create.getByText('离线主机将在上线后收到指令',{exact:false}).click()
  await create.getByRole('button',{name:'下发核查',exact:true}).click()
  await expect(page.getByText(/以下主机没有适用模板/)).toBeVisible()
  assert.equal(writes.filter(write=>write.path==='/api/baseline/tasks').length,0)
  rejectCoverage=false
  await create.getByRole('button',{name:'下发核查',exact:true}).click()
  await expect(create).not.toBeVisible()
  assert.deepEqual(writes.find(write=>write.path==='/api/baseline/tasks').body.templateIds,[])

  await page.goto('/baseline-templates');await page.setViewportSize({width:390,height:844})
  const windows=page.getByRole('row').filter({has:page.getByRole('cell',{name:'Windows 基础安全核查',exact:true})})
  await windows.getByRole('button',{name:'查看版本',exact:true}).click()
  await expect(dialog.getByRole('heading',{name:/Windows 基础安全核查/})).toBeVisible()
  const bounds=await dialog.boundingBox()
  assert.ok(bounds&&bounds.x>=0&&bounds.x+bounds.width<=390&&bounds.y>=0&&bounds.y+bounds.height<=844,'Mobile review dialog must fit the viewport')
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile page must not overflow')
  await page.screenshot({path:root+'/review-mobile.png',fullPage:true,animations:'disabled'})
  await dialog.getByRole('button',{name:'关闭',exact:true}).click()
  for(const role of ['viewer','operator']){
    await page.evaluate(role=>localStorage.setItem('alinksec_user',JSON.stringify({username:role,role})),role)
    await page.reload()
    await expect(page.getByRole('button',{name:'导入候选版本',exact:true})).toHaveCount(0)
    await page.getByRole('button',{name:'查看版本',exact:true}).first().click()
    await expect(dialog).toBeVisible()
    for(const action of ['审核通过','拒绝候选版本','下发测试核查','发布为可选模板','撤回版本'])await expect(dialog.getByRole('button',{name:action,exact:true})).toHaveCount(0)
    await dialog.getByRole('button',{name:'关闭',exact:true}).click()
  }
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
  writeFileSync(root+'/browser-result.json',JSON.stringify({passed:true,mode,checks:['Linux/Windows candidate import and metadata diff','review failure retains state','explicit test before publication','withdrawal','automatic mixed-system selection and uncovered hosts','administrator controls','mobile review dialog'],writes,errors,unexpected}))
  console.log('PASS baseline candidates, review, publication, OS selection, roles and mobile layout')
} catch(error) {
  writeFileSync(root+'/browser-result.json',JSON.stringify({passed:false,mode,error:error.message,writes,errors,unexpected}))
  await page?.screenshot({path:root+'/failure.png',fullPage:true,timeout:3000}).catch(()=>{})
  throw error
} finally {await browser?.close();await new Promise(resolve=>server.close(resolve))}
