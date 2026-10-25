package com.alinksec.service.report;

import com.alinksec.common.util.JsonUtils;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/** No templates, formulas, external workbook links or executable markup come from stored data. */
public final class ReportExport {
    private ReportExport(){}
    private record Table(String name,List<List<Object>> rows){}
    public static byte[] render(Map<String,Object> report,String format) {
        return switch(format){case "json"->JsonUtils.write(report).getBytes(StandardCharsets.UTF_8);
            case "csv"->csv(tables(report));case "xlsx"->xlsx(tables(report));case "html"->html(tables(report));
            default->throw new IllegalArgumentException("导出格式须为 csv、xlsx、html 或 json");};
    }
    public static String severity(Object value){return switch(((Number)value).intValue()){case 5->"危急（5）";case 4->"严重（4）";case 3->"高危（3）";case 2->"中危（2）";case 1->"低危（1）";default->"未知（"+value+"）";};}
    @SuppressWarnings("unchecked") private static List<Map<String,Object>> list(Map<String,Object> r,String key){return (List<Map<String,Object>>)r.get(key);}
    @SuppressWarnings("unchecked") private static Map<String,Object> map(Map<String,Object> r,String key){return (Map<String,Object>)r.get(key);}
    private static List<Object> row(Object...v){return Arrays.asList(v);}
    private static Table table(Map<String,Object> report,String key,String name,String[] fields,String[] labels) {
        var rows=new ArrayList<List<Object>>();rows.add(row((Object[])labels));
        for(var value:list(report,key)) {var cells=new ArrayList<Object>();for(String f:fields)cells.add(f.equals("severity")?(key.equals("alerts") && value.containsKey("severity_label")?value.get("severity_label"):severity(value.get(f))):value.get(f));rows.add(cells);}
        return new Table(name,rows);
    }
    private static List<Table> tables(Map<String,Object> r) {
        var overview=new ArrayList<List<Object>>();overview.add(row("指标","值"));overview.add(row("报表",r.get("title")));overview.add(row("生成时间（UTC）",r.get("generatedAt")));
        overview.add(row("统计内容摘要",r.get("dataDigest")));if(r.containsKey("snapshotId")){overview.add(row("快照标识",r.get("snapshotId")));overview.add(row("生成账号 ID",r.get("createdBy")));overview.add(row("保存期截至（UTC）",r.get("expiresAt")));}
        overview.add(row("自然日时区",r.get("timezone")));overview.add(row("开始日（含）",map(r,"query").get("from")));overview.add(row("结束日（含）",map(r,"query").get("to")));
        overview.add(row("分组",map(r,"scope").get("group")));overview.add(row("系统",map(r,"scope").get("os")));
        for(var e:Map.of("total","主机总数","online","在线","offline","离线","other","其他状态").entrySet())overview.add(row(e.getValue(),map(r,"assets").get(e.getKey())));
        for(var e:new String[][]{{"assigned_hosts","区间内分配基线的主机"},{"unassessed_hosts","区间内未分配基线的主机"},{"expected","预期自动检查项"},{"passed","通过"},{"failed","不通过"},{"errors","执行异常"},{"legacy","旧证据"},{"pending","待回报"}})overview.add(row(e[1],map(r,"baseline").get(e[0])));
        long expected=((Number)map(r,"baseline").get("expected")).longValue(),passed=((Number)map(r,"baseline").get("passed")).longValue();
        overview.add(row("自动检查通过率",expected==0?"无可计算分母":String.format(Locale.ROOT,"%.1f%%",passed*100.0/expected)));
        overview.add(row("主机明细条数 / 全部主机",list(r,"hosts").size()+" / "+r.get("detailTotal")));overview.add(row("明细是否截断",Boolean.TRUE.equals(r.get("detailsTruncated"))?"是；汇总仍覆盖全部所选主机":"否"));
        for(Object note:(List<?>)r.get("notes"))overview.add(row("统计口径",note));
        var tables=new ArrayList<Table>();tables.add(new Table("概览",overview));
        tables.add(table(r,"hosts","主机与基线",new String[]{"agent_id","hostname","os_type","status","task_id","task_name","expected","passed","failed","errors","legacy","pending"},new String[]{"Agent ID","主机","系统（1 Linux/2 Windows）","状态（1 在线/2 离线）","最后分配任务 ID","任务","预期项","通过","不通过","异常","旧证据","待回报"}));
        tables.add(table(r,"vulnerabilities","漏洞记录",new String[]{"severity","status","records","recorded_match"},new String[]{"等级","处置状态（0 新增/1 确认/2 忽略/3 已修复）","发现记录数","记录中仍匹配标记数（可能过期）"}));
        tables.add(table(r,"alerts","告警处置",new String[]{"severity","records","occurrences","handled","ignored","open"},new String[]{"等级","告警条数","合并发生次数","已处置","忽略","未处置"}));
        tables.add(table(r,"trend","每日趋势",new String[]{"day","alerts","vulnerabilities"},new String[]{"自然日","新增告警条数","新增漏洞记录数"}));
        tables.add(table(r,"coverage","漏洞覆盖",new String[]{"status","hosts"},new String[]{"采集或评估状态","主机数"}));
        var source=table(r,"sourceHolds","来源待处理",new String[]{"status","items"},new String[]{"CVE 声明状态","条数"});source.rows.add(row("范围",r.get("sourceHoldsScope")));tables.add(source);return tables;
    }
    private static byte[] csv(List<Table> tables) {
        var out=new StringBuilder("\uFEFF");
        for(var t:tables){out.append(csvCell("["+t.name+"]")).append("\r\n");for(var row:t.rows){for(int i=0;i<row.size();i++){if(i>0)out.append(',');out.append(csvCell(row.get(i)));}out.append("\r\n");}out.append("\r\n");}
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }
    private static String csvCell(Object value) {
        String text=value==null?"":value.toString();
        if(!(value instanceof Number)) {
            String significant=text.stripLeading().replaceFirst("^[\\p{Z}\\p{Cc}\\x{FEFF}]+","");
            if(!significant.isEmpty() && "=+-@".indexOf(significant.charAt(0))>=0 || !text.isEmpty() && "\t\r\n".indexOf(text.charAt(0))>=0)text="'"+text;
        }
        return "\""+text.replace("\"","\"\"")+"\"";
    }
    private static String xml(Object value) {
        String text=value==null?"":value.toString();var out=new StringBuilder();
        text.codePoints().forEach(c->{if(c==9 || c==10 || c==13 || c>=32 && c<=0xD7FF || c>=0xE000 && c<=0xFFFD || c>=0x10000 && c<=0x10FFFF)out.appendCodePoint(c);else out.append('\uFFFD');});
        return out.toString().replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");
    }
    private static void entry(ZipOutputStream zip,String name,String content)throws IOException {
        var e=new ZipEntry(name);e.setTime(0);zip.putNextEntry(e);zip.write(content.getBytes(StandardCharsets.UTF_8));zip.closeEntry();
    }
    private static byte[] xlsx(List<Table> tables) {
        try(var bytes=new ByteArrayOutputStream();var zip=new ZipOutputStream(bytes,StandardCharsets.UTF_8)) {
            String ns="http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            var types=new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>");
            var workbook=new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\""+ns+"\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>");
            var rels=new StringBuilder("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
            for(int i=0;i<tables.size();i++) {
                int id=i+1;Table t=tables.get(i);String name="worksheets/sheet"+id+".xml";
                types.append("<Override PartName=\"/xl/").append(name).append("\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
                workbook.append("<sheet name=\"").append(xml(t.name)).append("\" sheetId=\"").append(id).append("\" r:id=\"rId").append(id).append("\"/>");
                rels.append("<Relationship Id=\"rId").append(id).append("\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"").append(name).append("\"/>");
                var sheet=new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><worksheet xmlns=\""+ns+"\"><sheetData>");
                for(int n=0;n<t.rows.size();n++) {
                    sheet.append("<row r=\"").append(n+1).append("\">");int column=0;
                    for(Object value:t.rows.get(n)) {column++;String ref="";for(int c=column;c>0;c=(c-1)/26)ref=(char)('A'+(c-1)%26)+ref;
                        sheet.append("<c r=\"").append(ref).append(n+1).append("\"");
                        if(value instanceof Number)sheet.append("><v>").append(xml(value)).append("</v></c>");
                        else sheet.append(" t=\"inlineStr\"><is><t xml:space=\"preserve\">").append(xml(value)).append("</t></is></c>");
                    }sheet.append("</row>");
                }
                entry(zip,"xl/"+name,sheet.append("</sheetData></worksheet>").toString());
            }
            entry(zip,"[Content_Types].xml",types.append("</Types>").toString());entry(zip,"xl/workbook.xml",workbook.append("</sheets></workbook>").toString());
            entry(zip,"xl/_rels/workbook.xml.rels",rels.append("</Relationships>").toString());
            entry(zip,"_rels/.rels","<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>");
            zip.finish();return bytes.toByteArray();
        }catch(IOException e){throw new IllegalStateException("Excel 报表生成失败",e);}
    }
    private static byte[] html(List<Table> tables) {
        var out=new StringBuilder("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>ALinkSec 安全运营报表</title><style>body{font:14px system-ui,sans-serif;color:#172438;margin:24px}h1{font-size:22px}h2{font-size:18px;break-after:avoid}table{border-collapse:collapse;width:100%;margin:12px 0 24px;table-layout:fixed}td,th{border:1px solid #aab6c5;padding:6px;text-align:left;overflow-wrap:anywhere;white-space:pre-wrap}thead{display:table-header-group}tr{break-inside:avoid}th{background:#eef3f9}@page{size:A4 landscape;margin:12mm}@media print{body{margin:0;font-size:10px}}</style></head><body><h1>ALinkSec 安全运营报表</h1><p>可在浏览器中打印或另存为 PDF。</p>");
        for(var t:tables){out.append("<h2>").append(xml(t.name)).append("</h2><table>");for(int i=0;i<t.rows.size();i++){out.append(i==0?"<thead><tr>":"<tr>");String tag=i==0?"th":"td";for(Object v:t.rows.get(i))out.append('<').append(tag).append('>').append(xml(v)).append("</").append(tag).append('>');out.append(i==0?"</tr></thead><tbody>":"</tr>");}out.append("</tbody></table>");}
        return out.append("</body></html>").toString().getBytes(StandardCharsets.UTF_8);
    }
}
