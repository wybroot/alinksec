import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {createServer} from 'node:http'
import {dirname,resolve,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const dist=resolve(process.env.ALINKSEC_RANSOM_PREVIEW_DIST || resolve(web,'dist'))
const root=resolve(web,'../.tmp/windows-ransom-browser')
const fixture=JSON.parse(readFileSync(resolve(process.env.ALINKSEC_WINDOWS_RANSOM_BROWSER_FIXTURES || resolve(web,'../.tmp/windows-ransom-fixtures'),'alerts.json')))
mkdirSync(root,{recursive:true});assert.ok(existsSync(resolve(dist,'index.html')))
const server=createServer((req,res)=>{
 let file
 try{file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
 if(file!==dist&&!file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
 if(!existsSync(file)||!statSync(file).isFile())file=resolve(dist,'index.html')
 res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'}[extname(file)] || 'application/octet-stream')
 createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
const errors=[],unexpected=[],checks=[]
let browser,fail=true
try{
 async function launch(role){
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
  const context=await browser.newContext({viewport:{width:1440,height:1050}})
  await context.addInitScript(role=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:role,role}))},role)
  await context.route('**/api/**',route=>{
   const req=route.request(),path=new URL(req.url()).pathname
   if(req.method()!=='GET'||path!=='/api/alerts'){unexpected.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})}
   return fail?route.fulfill({status:503,json:{code:503,msg:'告警暂不可用'}}):route.fulfill({json:{code:0,data:fixture}})
  })
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/alerts`)
  return {context,page}
 }
 let {context,page}=await launch('viewer')
 await expect(page.getByRole('alert').filter({hasText:'告警暂不可用'})).toBeVisible()
 fail=false;await page.getByRole('button',{name:'重试',exact:true}).click()
 await expect(page.getByRole('button',{name:'查看归因证据'})).toHaveCount(5)
 checks.push('database-alert-read-failure-can-retry')
 await expect(page.getByRole('button',{name:'处置',exact:true})).toHaveCount(0)
 await expect(page.getByRole('button',{name:'忽略',exact:true})).toHaveCount(0)
 const seen=new Set(),births=new Set()
 for(let i=0;i<5;i++){
  await page.getByRole('button',{name:'查看归因证据'}).nth(i).click()
  const panel=page.getByTestId('ransom-attribution')
  await expect(panel).toBeVisible();const text=await panel.innerText()
  if(text.includes('已关联文件操作进程')){
   seen.add('attributed');for(const birth of ['134000000000000001','134000000000000002'])if(text.includes(birth))births.add(birth)
   await panel.locator('summary').click();await expect(panel).toContainText('C:\\data\\')
   await page.screenshot({path:root+'/attributed-desktop.png',animations:'disabled'})
  }
  if(text.includes('未确认写入者'))seen.add('unattributed')
  if(text.includes('存在多个写入者'))seen.add('ambiguous')
  await expect(panel).toContainText('并非当前主机监测状态')
  await page.getByRole('dialog').getByRole('button',{name:'Close this dialog'}).click()
 }
 assert.deepEqual([...seen].sort(),['ambiguous','attributed','unattributed']);assert.equal(births.size,2)
 checks.push('confirmed-unknown-ambiguous-evidence-and-exact-instance-identity')
 await page.setViewportSize({width:390,height:844})
 await page.getByRole('button',{name:'查看归因证据'}).first().click()
 const dialog=page.getByRole('dialog'),bounds=await dialog.boundingBox()
 assert.ok(bounds.x>=0&&bounds.x+bounds.width<=391)
 await page.screenshot({path:root+'/evidence-mobile.png',animations:'disabled'})
 checks.push('viewer-evidence-readonly-and-mobile-dialog-fits')
 await context.close();await browser.close();({context,page}=await launch('operator'))
 await expect(page.getByRole('button',{name:'处置',exact:true})).toHaveCount(5)
 await page.getByRole('button',{name:'查看归因证据'}).first().click();await expect(page.getByTestId('ransom-attribution')).toBeVisible()
 checks.push('operator-can-review-same-retained-evidence')
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,checks,errors,unexpected,mobileDialog:bounds},null,2)+'\n')
 console.log('Passed Windows ransomware evidence browser checks:',checks)
}finally{await browser?.close();await new Promise(done=>server.close(done))}
