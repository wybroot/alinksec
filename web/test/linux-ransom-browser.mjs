import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdirSync,existsSync,statSync,createReadStream} from 'node:fs'
import {createServer} from 'node:http'
import {dirname,resolve,extname,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import {chromium,expect} from '@playwright/test'
const web=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const dist=resolve(process.env.ALINKSEC_RANSOM_PREVIEW_DIST || resolve(web,'dist'))
const root=resolve(web,'../.tmp/linux-ransom-browser')
// Replay the actual native Agent event through the REST row shape. This checks
// presentation; database persistence is covered by WindowsRansomIntegrationTest.
const event=JSON.parse(readFileSync(resolve(process.env.ALINKSEC_LINUX_ATTRIB_EVIDENCE_FILE || resolve(web,'../.tmp/linux-ransom-native/event.json'))))
assert.equal(event.action_taken,'alert_only')
const detail=JSON.parse(event.detail)
assert.equal(detail.attribution.reason,'writer_evidence_unavailable')
assert.equal(detail.process,undefined)
const fixture={list:[{id:'linux-native',severity_level:4,severity_source:'agent_proto_v1',event_type:event.type,title:event.rule_name,agent_id:'linux-native',detail:event.detail,action_taken:event.action_taken,status:0}],total:1}
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
let browser
try {
 for(const role of ['viewer','operator']) {
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote','--disable-gpu','--js-flags=--max-old-space-size=128']})
  const context=await browser.newContext({viewport:{width:1440,height:1050}})
  await context.addInitScript(role=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:role,role}))},role)
  await context.route('**/api/**',route=>{
   const req=route.request(),path=new URL(req.url()).pathname
   if(req.method()!=='GET'||path!=='/api/alerts'){unexpected.push(req.method()+' '+path);return route.fulfill({status:500,json:{code:500,msg:'Unexpected request'}})}
   return route.fulfill({json:{code:0,data:fixture}})
  })
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/alerts`)
  await expect(page.getByRole('button',{name:'处置',exact:true})).toHaveCount(role==='viewer'?0:1)
  await page.getByRole('button',{name:'查看归因证据',exact:true}).click()
  const panel=page.getByTestId('ransom-attribution')
  await expect(panel).toContainText('Linux 尚无可信写入者证据')
  await expect(panel).toContainText('已跳过进程终止')
  await expect(panel).toContainText('实际响应：仅告警')
  await expect(panel).toContainText('主机隔离仍按配置独立执行')
  await expect(panel.locator('dt')).toHaveCount(0)
  await expect(panel.locator('summary')).toHaveCount(0)
  await page.screenshot({path:root+'/'+role+'-desktop.png',animations:'disabled'})
  await page.setViewportSize({width:390,height:844})
  const dialog=page.getByRole('dialog').locator('.el-dialog')
  await expect(dialog).toHaveCSS('opacity','1')
  const bounds=await dialog.boundingBox()
  assert.ok(bounds.x>=0&&bounds.y>=0&&bounds.x+bounds.width<=391)
  assert.ok(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth))
  await page.screenshot({path:root+'/'+role+'-mobile.png',animations:'disabled'})
  checks.push(role+'-missing-writer-reason-no-false-kill-and-mobile-layout')
  await context.close();await browser.close()
 }
 assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
 writeFileSync(root+'/result.json',JSON.stringify({passed:true,scope:process.env.ALINKSEC_RANSOM_PREVIEW_DIST?'page-scoped-current-source-preview':'production-bundle',checks,errors,unexpected},null,2)+'\n')
 console.log('Passed Linux ransomware missing-writer browser checks:',checks)
}finally{await browser?.close();await new Promise(done=>server.close(done))}
