import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { chromium, expect } from '@playwright/test'

const web=resolve(dirname(fileURLToPath(import.meta.url)),'..'),dist=resolve(web,'dist')
const fixtures=resolve(web,'../.tmp/report-fixtures'),root=resolve(web,'../.tmp/report-browser/severity')
mkdirSync(root,{recursive:true})
const errors=[],unexpected=[],checks=[],screenshots=[]
const server=createServer((req,res)=>{
  let file;try{file=resolve(dist,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname))}catch{res.writeHead(400);res.end();return}
  if(!file.startsWith(dist+sep)){res.writeHead(403);res.end();return}
  if(!existsSync(file)||!statSync(file).isFile())file=resolve(dist,'index.html')
  res.setHeader('Content-Type',{'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml'}[extname(file)]||'application/octet-stream')
  createReadStream(file).on('error',()=>res.destroy()).pipe(res)
})
await new Promise(done=>server.listen(0,'127.0.0.1',done))
let browser
try {
  browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']})
  for(const database of ['sqlite','postgres']) {
    const fixture=JSON.parse(readFileSync(resolve(fixtures,'severity-'+database+'.json')))
    assert.equal(fixture.database,database)
    const context=await browser.newContext({viewport:{width:1440,height:1000}})
    context.setDefaultTimeout(10000)
    await context.addInitScript(()=>{localStorage.setItem('alinksec_token','fixture');localStorage.setItem('alinksec_user',JSON.stringify({username:'fixture',role:'viewer'}))})
    await context.route('**/api/**',route=>{
      const path=new URL(route.request().url()).pathname
      if(route.request().method()==='GET'&&path==='/api/alerts')return route.fulfill({json:{code:0,data:fixture.alerts}})
      unexpected.push(route.request().method()+' '+path);return route.fulfill({status:500,json:{code:50000,msg:'Unexpected request'}})
    })
    const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message))
    await page.goto('http://127.0.0.1:'+server.address().port+'/alerts')
    const rows=page.locator('.el-table__body-wrapper tbody tr')
    await expect(rows).toHaveCount(fixture.alerts.list.length)
    // Exact source/number matches come from actual migrated database captures.
    for(const item of fixture.alerts.list) {
      const label={0:'信息',1:'低危',2:'中危',3:'高危',4:'严重','-1':'未知'}[item.severity_level]
      const actual=rows.filter({hasText:item.title})
      if(item.rule_id!=='same'&&item.rule_id!=='changing')await expect(actual).toContainText(label)
    }
    const legacy=rows.filter({hasText:'Historical'});await expect(legacy).toContainText('严重');await expect(legacy).toContainText('历史等级，沿用旧含义')
    await page.getByRole('tab',{name:'严重',exact:true}).click()
    await expect(rows).toHaveCount(2);await expect(rows.filter({hasText:'Historical'})).toHaveCount(1);await expect(rows.filter({hasText:'critical'})).toHaveCount(1)
    await page.getByRole('tab',{name:'高危',exact:true}).click()
    await expect(rows).toHaveCount(2);await expect(rows.filter({hasText:'Historical'})).toHaveCount(0)
    checks.push(database+':source_levels_history_and_filters')
    await page.getByRole('tab',{name:'全部',exact:true}).click()
    for(const [size,viewport] of [['desktop',{width:1440,height:1000}],['mobile',{width:390,height:844}]]) {
      await page.setViewportSize(viewport)
      const name=database+'-'+size+'.png',path=resolve(root,name)
      await page.screenshot({path,animations:'disabled',fullPage:true})
      screenshots.push({name,sha256:createHash('sha256').update(readFileSync(path)).digest('hex')})
    }
    await context.close()
  }
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[])
} finally {
  writeFileSync(resolve(root,'result.json'),JSON.stringify({passed:checks.length===2&&screenshots.length===4&&errors.length===0&&unexpected.length===0,checks,errors,unexpected,screenshots},null,2)+'\n')
  if(browser)await browser.close();await new Promise(done=>server.close(done))
}
console.log('Source-aware severity: both database captures, filters and four rendered views passed')
