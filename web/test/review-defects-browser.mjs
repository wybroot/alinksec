import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {resolve,dirname,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const dist=resolve(process.env.ALINKSEC_REVIEW_PREVIEW_DIST || process.env.ALINKSEC_REVIEW_ROUTED_PREVIEW_DIST || resolve(web,'dist'))
const root=resolve(process.env.ALINKSEC_REVIEW_BROWSER_ARTIFACTS || resolve(web,'../.tmp/review-defects-browser'));mkdirSync(root,{recursive:true})
const server=createServer((req,res)=>{
 let path=resolve(dist,'.'+new URL(req.url,'http://localhost').pathname)
 if(path!==dist&&!path.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(path)||!statSync(path).isFile())path=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html'}[extname(path)] || 'application/octet-stream');createReadStream(path).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
const checks=[],errors=[],posts=[]
let slowCritical=false,releaseSlow,startedSlow
const slowStarted=new Promise(resolve=>startedSlow=resolve)
let browser
try{
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
 const context=await browser.newContext({viewport:{width:1280,height:900}})
 await context.addInitScript(()=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({role:'admin',username:'admin'}))})
 const userRows=[{id:1,username:'admin',role:'admin',status:1,auth_version:0}]
 const alerts=Array.from({length:105},(_,i)=>({id:i+1,title:'alert-'+(i+1),event_type:'process',severity_level:i>=100?4:2,status:i>=100?0:2,detail:'{}'}))
 await context.route('**/api/**',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname
  if(path==='/api/alerts'&&req.method()==='GET'){
   const q=url.searchParams,p=Number(q.get('page')),size=Number(q.get('size'))
   if(slowCritical&&q.get('severity')==='4'){startedSlow();await new Promise(resolve=>releaseSlow=resolve)}
   let rows=alerts.filter(a=>(q.get('status')!=='-1'||a.status!==2)&&(!q.has('severity')||a.severity_level>=Number(q.get('severity')))&&(!q.has('maxSeverity')||a.severity_level<=Number(q.get('maxSeverity'))))
   return route.fulfill({json:{code:0,data:{list:rows.slice((p-1)*size,p*size),total:rows.length}}})
  }
  if(path.match(/^\/api\/alerts\/\d+\/handle$/)&&req.method()==='POST'){
   posts.push({path,body:req.postDataJSON()});alerts.find(a=>a.id===Number(path.split('/')[3])).status=2
   return route.fulfill({json:{code:0,data:null}})
  }
  if(path==='/api/users'&&req.method()==='GET')return route.fulfill({json:{code:0,data:{list:userRows,total:userRows.length}}})
  if(path==='/api/users'&&req.method()==='POST'){const body=req.postDataJSON();posts.push({path,body});userRows.push({id:2,username:body.username,role:body.role,status:1,auth_version:0});return route.fulfill({json:{code:0,data:null}})}
  if(path==='/api/users/2'&&req.method()==='PUT'){posts.push({path,body:req.postDataJSON()});return route.fulfill({json:{code:0,data:null}})}
  if(path==='/api/auth/password'&&req.method()==='POST'){posts.push({path,body:{oldPassword:'[redacted]',password:'[redacted]'}});return route.fulfill({status:400,json:{code:10001,msg:'原密码不正确'}})}
  if(!process.env.ALINKSEC_REVIEW_PREVIEW_DIST && req.method()==='GET' && (path.startsWith('/api/upgrade/') || path.startsWith('/api/notify/') || path.startsWith('/api/audit')))return route.fulfill({json:{code:0,data:[]}})
  errors.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})
 })
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
 await page.goto(`http://127.0.0.1:${server.address().port}/alerts`)
 await expect(page.locator('.el-table__body tr')).toHaveCount(100)
 await page.locator('.btn-next').click();await expect(page.locator('.el-table__body tr')).toHaveCount(5);await expect(page.locator('.el-table')).toContainText('alert-105')
 await page.getByRole('tab',{name:'待处置',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(5)
 await page.getByRole('button',{name:'标记已处理',exact:true}).first().click()
 await expect(page.getByText('已标记处理；未下发主机动作',{exact:true})).toBeVisible();await expect(page.locator('.el-table__body tr')).toHaveCount(4)
 assert.equal(posts.length,1);assert.match(posts[0].path,/\/handle$/);assert.equal(posts[0].body.remark,'标记已处理')
 checks.push('server-pagination-older-open-alerts-and-honest-handled-action')
 slowCritical=true;await page.getByRole('tab',{name:'严重',exact:true}).click();await slowStarted
 await page.getByRole('tab',{name:'全部',exact:true}).click();await expect(page.locator('.el-table__body tr')).toHaveCount(100)
 const delayed=page.waitForResponse(response=>response.url().includes('severity=4'));releaseSlow();await delayed;await page.waitForTimeout(100)
 await expect(page.locator('.el-table__body tr')).toHaveCount(100);checks.push('late-response-does-not-overwrite-new-filter')
 await page.goto(`http://127.0.0.1:${server.address().port}/${process.env.ALINKSEC_REVIEW_PREVIEW_DIST?'users':'system'}`)
 if(!process.env.ALINKSEC_REVIEW_PREVIEW_DIST)await page.getByRole('tab',{name:'用户管理',exact:true}).click()
 await page.getByRole('button',{name:'创建用户',exact:true}).click()
 await page.getByRole('dialog').locator('input').nth(0).fill('operator-test')
 await page.getByRole('dialog').locator('input').nth(1).fill('操作员')
 await page.getByRole('dialog').locator('input[type=password]').fill('Temporary-test-password-123')
 await page.getByRole('dialog').getByRole('button',{name:'保存',exact:true}).click()
 await expect(page.getByRole('dialog')).toHaveCount(0)
 assert.equal(posts.at(-1).path,'/api/users');assert.equal(posts.at(-1).body.role,'viewer')
 checks.push('admin-user-create-defaults-to-readonly-role')
 await page.getByRole('button',{name:'编辑／重置密码',exact:true}).last().click();await page.getByRole('dialog').locator('.el-switch').click();await expect(page.getByRole('dialog').getByRole('switch')).not.toBeChecked();await page.getByRole('dialog').getByRole('button',{name:'保存',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0)
 assert.equal(posts.at(-1).path,'/api/users/2');assert.equal(posts.at(-1).body.status,'0');assert.equal(posts.at(-1).body.version,'0');assert.equal(Object.hasOwn(posts.at(-1).body,'password'),false);checks.push('admin-edit-sends-version-and-preserves-unchanged-password')
 if(process.env.ALINKSEC_REVIEW_PREVIEW_DIST)await page.goto(`http://127.0.0.1:${server.address().port}/password`)
 else{await page.locator('header .el-dropdown').click();await page.getByText('修改密码',{exact:true}).click()}
 const dialog=page.getByRole('dialog');await dialog.locator('input').nth(0).fill('wrong-password');await dialog.locator('input').nth(1).fill('New-test-password-123');await dialog.locator('input').nth(2).fill('different-password')
 const before=posts.length;await dialog.getByRole('button',{name:'修改密码',exact:true}).click();await expect(dialog).toContainText('两次新密码不一致');assert.equal(posts.length,before)
 await dialog.locator('input').nth(2).fill('New-test-password-123');await dialog.getByRole('button',{name:'修改密码',exact:true}).click();await expect(dialog).toContainText('原密码不正确')
 checks.push('password-confirmation-and-server-rejection-remain-visible')
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:root+'/password-mobile.png',animations:'disabled'})
 assert.deepEqual(errors,[])
 // Never retain submitted credentials in browser artifacts.
 const scope=process.env.ALINKSEC_REVIEW_PREVIEW_DIST?'current-source-page-preview':process.env.ALINKSEC_REVIEW_ROUTED_PREVIEW_DIST?'current-source-routed-preview':'production-bundle'
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,scope,checks,errors},null,2)+'\n')
 console.log('Passed defect browser checks:',checks)
 await context.close()
}finally{await browser?.close();await new Promise(done=>server.close(done))}
