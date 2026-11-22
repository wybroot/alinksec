import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {createHash} from 'node:crypto'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {resolve,dirname,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'

const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const fixture=resolve(process.env.ALINKSEC_CONSOLE_FIXTURE || resolve(web,'../.tmp/review-console/sqlite'))
const cases=JSON.parse(readFileSync(fixture+'/cases.json','utf8'))
const account=JSON.parse(readFileSync(fixture+'/account-facts.json','utf8'))
const dist=resolve(process.env.ALINKSEC_CONSOLE_PREVIEW_DIST || resolve(web,'dist'))
const output=fixture+'/browser';mkdirSync(output,{recursive:true})
const checks=[],errors=[],requests=[],screenshots=[]
const sha=value=>createHash('sha256').update(value).digest('hex')
const server=createServer((req,res)=>{
 let path=resolve(dist,'.'+new URL(req.url,'http://localhost').pathname)
 if(path!==dist&&!path.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(path)||!statSync(path).isFile())path=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html'}[extname(path)] || 'application/octet-stream');createReadStream(path).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
const base=`http://127.0.0.1:${server.address().port}`
let browser
const launch=()=>chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
async function snapshot(page,name){await page.screenshot({path:output+'/'+name+'.png',animations:'disabled'});screenshots.push(name+'.png')}
try {
 browser=await launch()
 async function session(role){
  const context=await browser.newContext({viewport:{width:1280,height:900}})
  const profile=cases[role==='admin'?'new-password-login':role+'-role-login'].response.data.user
  await context.addInitScript(profile=>{if(location.protocol==='http:'&&!sessionStorage.getItem('initialized')){localStorage.setItem('alinksec_token','sanitized-captured-token');localStorage.setItem('alinksec_user',JSON.stringify(profile));sessionStorage.setItem('initialized','1')}},profile)
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));return {context,page}
 }
 const {context,page}=await session('admin')
 let handled=false,duplicate=false,handleFailure=false,alertFailure=false,passwordSuccess=false,loginSuccess=false,userStage='users-before-create',editStage=0
 let slowCritical=false,releaseSlow,startedSlow
 const slowStarted=new Promise(done=>startedSlow=done)
 async function respond(route,name){
  const row=cases[name];assert.ok(row,'missing original captured response: '+name)
  const req=route.request()
  assert.equal(req.method(),row.method)
  assert.equal(new URL(req.url()).pathname,new URL(row.path,'http://capture').pathname)
  requests.push({method:req.method(),path:new URL(req.url()).pathname,query:new URL(req.url()).search,case:name,status:row.status,responseSHA256:sha(JSON.stringify(row.response))})
  await route.fulfill({status:row.status,json:row.response})
 }
 await context.route('**/api/**',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname
  if(req.method()==='GET'&&path==='/api/alerts'){
   if(alertFailure){requests.push({method:'GET',path,injectedTransportFailure:true});return route.abort('connectionfailed')}
   const q=url.searchParams
   if(slowCritical&&q.get('severity')==='4'){startedSlow();await new Promise(done=>releaseSlow=done)}
   const name=q.get('status')==='-1'?(handled?'alerts-open-after-handle':'alerts-open'):q.get('severity')==='4'?'alerts-critical':q.get('severity')==='3'?'alerts-empty':q.get('page')==='2'?'alerts-page-two':handled?'alerts-all-after-handle':'alerts-page-one'
   return respond(route,name)
  }
  if(req.method()==='POST'&&path.match(/^\/api\/alerts\/\d+\/handle$/)){
   if(handleFailure){requests.push({method:'POST',path,injectedTransportFailure:true});return route.abort('connectionfailed')}
   assert.equal(req.postDataJSON().remark,'标记已处理');handled=true;return respond(route,duplicate?'alert-duplicate-denied':'alert-handled')
  }
  if(req.method()==='GET'&&path==='/api/users')return respond(route,userStage)
  if(req.method()==='POST'&&path==='/api/users'){
   const body=req.postDataJSON();assert.equal(body.username,'console-managed');assert.equal(body.role,'viewer');assert.ok(body.password);userStage='users-created';return respond(route,'user-created')
  }
  if(req.method()==='PUT'&&path==='/api/users/'+account.managedUserId){
   const body=req.postDataJSON();assert.equal(body.version,String(editStage));
   if(editStage===0){assert.equal(body.role,'operator');assert.equal(body.status,'1');assert.equal(Object.hasOwn(body,'password'),false);userStage='users-promoted'}
   if(editStage===1){assert.equal(body.role,'operator');assert.equal(body.status,'0');assert.equal(Object.hasOwn(body,'password'),false);userStage='users-disabled'}
   if(editStage===2){assert.equal(body.role,'viewer');assert.equal(body.status,'1');assert.ok(body.password);userStage='users-reset'}
   return respond(route,['user-promoted','user-disabled','user-reset'][editStage++])
  }
  if(req.method()==='POST'&&path==='/api/auth/password')return respond(route,passwordSuccess?'password-changed':'password-rejected')
  if(req.method()==='POST'&&path==='/api/auth/login')return respond(route,loginSuccess?'new-password-login':'old-password-login-denied')
  if(req.method()==='GET'&&cases['ancillary:'+path+url.search])return respond(route,'ancillary:'+path+url.search)
  errors.push(req.method()+' '+path);await route.fulfill({status:500,json:{code:500,msg:'Unexpected acceptance request'}})
 })
 await page.goto(base+'/alerts');await expect(page.locator('.el-table__body tr')).toHaveCount(100)
 await page.locator('.btn-next').click();await expect(page.locator('.el-table__body tr')).toHaveCount(5);await expect(page.locator('.el-table')).toContainText('console-alert-0')
 await snapshot(page,'alerts-page-two');checks.push('actual-105-alert-capture-second-page-includes-oldest-open-alert')
 await page.getByRole('tab',{name:'待处置',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(1)
 handleFailure=true;await page.getByRole('button',{name:'标记已处理',exact:true}).click();await expect(page.locator('.el-message--error')).toBeVisible();await expect(page.locator('.el-table__body tr')).toHaveCount(1);handleFailure=false;checks.push('injected-marking-network-failure-is-visible-and-preserves-open-row')
 await page.getByRole('button',{name:'标记已处理',exact:true}).click();await expect(page.getByText('已标记处理；未下发主机动作',{exact:true})).toBeVisible();await expect(page.locator('.el-table__body tr')).toHaveCount(0)
 await snapshot(page,'alerts-handled-empty');checks.push('captured-success-clears-open-filter-and-states-no-host-action')
 // Replay the actual duplicate rejection against a stale page, as another administrator can have handled it.
 handled=false;duplicate=true;await page.getByRole('tab',{name:'全部',exact:true}).click();await page.getByRole('tab',{name:'待处置',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(1)
 await page.getByRole('button',{name:'标记已处理',exact:true}).click();await expect(page.getByText('告警不存在或已处置',{exact:true})).toBeVisible();await expect(page.locator('.el-table__body tr')).toHaveCount(0);checks.push('captured-duplicate-rejection-is-visible-and-reloads-terminal-state')
 await page.getByRole('tab',{name:'高危',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(0);await expect(page.locator('.el-table__empty-text')).toBeVisible();checks.push('actual-empty-filter-is-visible')
 alertFailure=true;await page.getByRole('tab',{name:'全部',exact:true}).click();await expect(page.locator('p[role=alert]')).toBeVisible();await expect(page.locator('.el-table__body tr')).toHaveCount(0)
 await snapshot(page,'alerts-load-error');alertFailure=false;await page.getByRole('button',{name:'重试',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(100);checks.push('injected-network-failure-clears-data-and-retry-recovers')
 slowCritical=true;await page.getByRole('tab',{name:'严重',exact:true}).click();await slowStarted;await page.getByRole('tab',{name:'全部',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(100)
 const delayed=page.waitForResponse(res=>res.url().includes('severity=4'));releaseSlow();await delayed;await page.waitForTimeout(100);await expect(page.locator('.el-table__body tr')).toHaveCount(100);checks.push('delayed-captured-filter-response-cannot-replace-newer-page')
 await page.goto(base+'/system');await page.getByRole('tab',{name:'用户管理',exact:true}).click();await page.getByRole('button',{name:'创建用户',exact:true}).click()
 let dialog=page.getByRole('dialog');await dialog.locator('input').nth(0).fill('console-managed');await dialog.locator('input').nth(1).fill('console fixture');await dialog.locator('input[type=password]').fill('Browser-placeholder-123');await dialog.getByRole('button',{name:'保存',exact:true}).click();await expect(dialog).toHaveCount(0)
 async function edit(role,disable,password){
  await page.locator('.el-table__body tr').filter({hasText:'console-managed'}).getByRole('button',{name:'编辑／重置密码',exact:true}).click();const d=page.getByRole('dialog')
  if(role){await d.locator('.el-select').click();await page.getByRole('option',{name:role,exact:true}).click()}
  if(disable)await d.locator('.el-switch').click()
  if(password)await d.locator('input[type=password]').fill('Browser-reset-placeholder-123')
  await d.getByRole('button',{name:'保存',exact:true}).click();await expect(d).toHaveCount(0)
 }
 await edit('operator',false,false);await edit(null,true,false);await edit('viewer',true,true);assert.equal(editStage,3);await snapshot(page,'admin-account-management');checks.push('captured-create-promote-disable-reset-with-version-and-password-preservation')
 await page.locator('header .el-dropdown').click();await page.getByText('修改密码',{exact:true}).click();dialog=page.getByRole('dialog')
 await dialog.locator('input').nth(0).fill('Browser-old-placeholder-123');await dialog.locator('input').nth(1).fill('Browser-new-placeholder-123');await dialog.locator('input').nth(2).fill('mismatch')
 const before=requests.length;await dialog.getByRole('button',{name:'修改密码',exact:true}).click();await expect(dialog).toContainText('两次新密码不一致');assert.equal(requests.length,before)
 await dialog.locator('input').nth(2).fill('Browser-new-placeholder-123');await dialog.getByRole('button',{name:'修改密码',exact:true}).click();await expect(dialog).toContainText('原密码不正确');await page.setViewportSize({width:390,height:844});await snapshot(page,'password-mobile-error')
 passwordSuccess=true;await dialog.getByRole('button',{name:'修改密码',exact:true}).click();await expect(page).toHaveURL(base+'/login')
 assert.deepEqual(await page.evaluate(()=>[localStorage.getItem('alinksec_token'),localStorage.getItem('alinksec_user')]),[null,null]);checks.push('password-confirmation-rejection-and-success-clear-session-and-redirect')
 await page.goto(base+'/login?redirect=/alerts');await page.getByPlaceholder('用户名',{exact:true}).fill('admin');await page.getByPlaceholder('密码',{exact:true}).fill('Browser-old-placeholder-123');await page.getByRole('button',{name:'登 录',exact:true}).click();await expect(page.getByText('用户名或密码错误',{exact:true})).toBeVisible();await expect(page).toHaveURL(base+'/login?redirect=/alerts')
 loginSuccess=true;await page.getByPlaceholder('密码',{exact:true}).fill('Browser-new-placeholder-123');await page.getByRole('button',{name:'登 录',exact:true}).click();await expect(page).toHaveURL(base+'/alerts');await expect(page.locator('.el-table__body tr')).toHaveCount(100);checks.push('captured-old-password-denial-and-new-password-login')
 await context.close()
 await browser.close()
 for(const role of ['viewer','operator']){
  browser=await launch()
  const {context,page}=await session(role)
  await context.route('**/api/**',async route=>{
   const url=new URL(route.request().url())
   if(role==='viewer'&&url.pathname==='/api/auth/password'&&route.request().method()==='POST')return respond(route,'viewer-password-changed')
   if(url.pathname==='/api/alerts')return respond(route,url.searchParams.get('status')==='-1'?'alerts-open':'alerts-page-one')
   if(cases['ancillary:'+url.pathname+url.search])return respond(route,'ancillary:'+url.pathname+url.search)
   errors.push(role+':'+url.pathname);return route.abort()
  })
  await page.goto(base+'/alerts');await expect(page.locator('.el-table__body tr')).toHaveCount(100);await page.getByRole('tab',{name:'待处置',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(1);await expect(page.getByRole('button',{name:'标记已处理',exact:true})).toHaveCount(role==='viewer'?0:1)
  await page.goto(base+'/system');await expect(page.getByRole('tab',{name:'用户管理',exact:true})).toHaveCount(0);await snapshot(page,role+'-permission-boundary');checks.push(role+'-page-permission-controls')
  if(role==='viewer'){
   await page.locator('header .el-dropdown').click();await page.getByText('修改密码',{exact:true}).click();const d=page.getByRole('dialog')
   for(const [i,value] of ['Viewer-old-placeholder-123','Viewer-new-placeholder-123','Viewer-new-placeholder-123'].entries())await d.locator('input').nth(i).fill(value)
   await d.getByRole('button',{name:'修改密码',exact:true}).click();await expect(page).toHaveURL(base+'/login');assert.equal(await page.evaluate(()=>localStorage.getItem('alinksec_token')),null);checks.push('viewer-self-service-password-clears-session')
  }
  await context.close()
  await browser.close()
 }
 assert.deepEqual(errors,[])
 writeFileSync(output+'/result.json',JSON.stringify({passed:true,scope:process.env.ALINKSEC_CONSOLE_PREVIEW_DIST?'current-source-routed-preview':'production-bundle',
  backendBrowserOverlap:false,responses:'sanitized captures of real isolated HTTP operations; transport failure and delay injected in browser',
  casesSHA256:sha(readFileSync(fixture+'/cases.json')),checks,requests,errors,screenshots:Object.fromEntries(screenshots.map(name=>[name,sha(readFileSync(output+'/'+name))]))},null,2)+'\n')
 console.log('Console captured-response browser checks passed:',checks.length)
} finally {await browser?.close();await new Promise(done=>server.close(done))}
