import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {createServer} from 'node:http'
import {dirname,resolve,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const preview=process.env.ALINKSEC_LIBRARY_PREVIEW_DIST
const dist=preview ? resolve(preview) : resolve(web,'dist')
const root=resolve(web,preview ? '../.tmp/library-preview-artifacts' : '../.tmp/library-browser-artifacts')
const mode=`${preview ? 'page preview' : 'production web bundle'}; captured PostgreSQL fixture responses`
assert.ok(existsSync(resolve(dist,'index.html')),'Build the selected web bundle before this check')
mkdirSync(root,{recursive:true})
const fixtures=JSON.parse(readFileSync(new URL('./fixtures/library-schedules.json',import.meta.url)))
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
const errors=[],writes=[],unexpectedRequests=[]
let rejectSchedule=false
let browser,page
process.once('SIGTERM',async()=>{await browser?.close();process.exit(1)})
try {
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
  const context=await browser.newContext({viewport:{width:1440,height:1000},baseURL})
  context.setDefaultTimeout(5000)
  await context.addInitScript(()=>{if(!localStorage.getItem('alinksec_token')){localStorage.setItem('alinksec_token','browser-fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'admin',role:'admin'}))}})
  const state=structuredClone(fixtures.managed)
  await context.route('**/api/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname,method=request.method()
    if(path==='/api/libraries')return route.fulfill({json:{code:0,data:state}})
    if(path.endsWith('/runs'))return route.fulfill({json:{code:0,data:fixtures.runs}})
    if(path.endsWith('/schedule')){
      const id=path.split('/')[4],source=state.sources.find(x=>x.id===id)
      if(method==='PUT'){
        if(rejectSchedule)return route.fulfill({status:400,json:{code:400,msg:'同步计划保存失败，请重试'}})
        const plan=request.postDataJSON();writes.push({method,id,...plan})
        Object.assign(source,plan,{scheduleOverridden:true})
      } else if(method==='DELETE'){
        writes.push({method,id});Object.assign(source,{enabled:true,intervalMs:300000,scheduleOverridden:false})
      }
      return route.fulfill({json:{code:0,data:{enabled:source.enabled,intervalMs:source.intervalMs,overridden:source.scheduleOverridden}}})
    }
    unexpectedRequests.push(`${method} ${path}`)
    return route.fulfill({status:500,json:{code:500,msg:'Unexpected API request'}})
  })
  page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
  await page.goto('/libraries')
  await expect(page.getByRole('heading',{name:'安全库管理'})).toBeVisible()
  const misp=page.getByRole('row').filter({has:page.getByRole('cell',{name:'misp-source',exact:true})})
  await expect(misp.getByRole('cell',{name:/^MISP 文件情报/})).toBeVisible()
  await expect(misp.getByText('已审核哈希的完整快照',{exact:true})).toBeVisible()
  await page.getByRole('button',{name:'同步计划',exact:true}).first().click()
  let dialog=page.getByRole('dialog',{name:'同步计划',exact:true})
  await dialog.locator('.el-switch').click()
  await dialog.getByRole('spinbutton').fill('35')
  await dialog.getByRole('button',{name:'保存',exact:true}).click()
  await expect(dialog).not.toBeVisible()
  assert.deepEqual(writes[0],{method:'PUT',id:'local-feed',enabled:true,intervalMs:2100000})
  await expect(page.getByText('35 分钟',{exact:true})).toBeVisible()
  await page.getByRole('button',{name:'同步计划',exact:true}).first().click()
  rejectSchedule=true
  await dialog.getByRole('spinbutton').fill('40')
  await dialog.getByRole('button',{name:'保存',exact:true}).click()
  await expect(page.getByText('同步计划保存失败，请重试',{exact:true})).toBeVisible()
  await expect(dialog).toBeVisible()
  assert.equal(writes.length,1,'A rejected schedule must leave the saved plan intact')
  await expect(page.getByText('35 分钟',{exact:true})).toBeVisible()
  rejectSchedule=false
  await dialog.getByRole('button',{name:'恢复部署配置',exact:true}).click()
  await expect(dialog).not.toBeVisible()
  assert.deepEqual(writes[1],{method:'DELETE',id:'local-feed'})
  await page.getByRole('button',{name:'执行记录',exact:true}).nth(1).click()
  let history=page.getByRole('dialog',{name:'misp-source · 最近执行记录'})
  await expect(history.getByText('失败',{exact:true})).toBeVisible()
  await expect(history.getByText('成功',{exact:true})).toHaveCount(2)
  await history.locator('.el-dialog__headerbtn').click()
  await page.screenshot({path:root+'/schedules-desktop.png',fullPage:true})
  await page.setViewportSize({width:390,height:844})
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile page overflow')
  await page.getByRole('button',{name:'同步计划',exact:true}).first().click()
  await expect(dialog.getByRole('spinbutton')).toBeVisible()
  await page.screenshot({path:root+'/schedule-mobile.png',fullPage:true})
  await dialog.getByRole('button',{name:'取消',exact:true}).click()
  for(const role of ['viewer','operator']){
    await page.evaluate(role=>localStorage.setItem('alinksec_user',JSON.stringify({username:role,role})),role)
    await page.reload()
    await expect(page.getByRole('heading',{name:'安全库管理'})).toBeVisible()
    await expect(page.getByRole('button',{name:'同步计划',exact:true})).toHaveCount(0)
    await expect(page.getByRole('button',{name:'立即同步',exact:true})).toHaveCount(0)
    await expect(page.getByRole('button',{name:'执行记录',exact:true})).toHaveCount(2)
    await expect(page.getByRole('button',{name:'导入病毒特征库',exact:true})).toHaveCount(role==='operator'?1:0)
  }
  assert.deepEqual(errors,[])
  assert.deepEqual(unexpectedRequests,[])
  writeFileSync(root+'/browser-result.json',JSON.stringify({passed:true,mode,checks:['schedule save, rejection and reset','execution history','MISP source display','viewer/operator rights','mobile dialog and page width'],writes,errors}))
  console.log('PASS console schedules, history, MISP display, roles and desktop/mobile layouts')
} catch(error) {
  writeFileSync(root+'/browser-result.json',JSON.stringify({passed:false,mode,error:error.message,writes,errors,unexpectedRequests}))
  await page?.screenshot({path:root+'/failure.png',fullPage:true,timeout:3000}).catch(()=>{})
  throw error
} finally {await browser?.close();await new Promise(r=>server.close(r))}
