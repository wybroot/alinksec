# 受保护业务站点接入 WAF 防护指南 (OWASP CRS / Coraza / ModSecurity)

> **2026-11-06 状态更新：** 经第 13 轮缺陷修复（R06、R07、R08、R60）：平台过滤器已接入请求正文缓存与检测、多重 URL 编码递归解包、Cookie/Header 深度检测与 PL1-4 多层异常评分；配置已接入 `t_system_config` 持久化热更新；`update-crs.py` 补齐真实下载、SHA-256 校验与回滚能力；Agent 日志采集已接通 `/var/log/nginx/modsec_audit.log` 审计日志自动转化为平台 `web_attack` 安全告警。外部独立反代部署需配置 ModSecurity/Coraza 生成对应格式日志。

本文档面向系统管理员与安全运维工程师，指导如何将受 ALinkSec Agent 监控的 Linux 主机上的业务 Web 服务接入 WAF 检查与实时防护体系。

---

## 1. 架构与接入模式

ALinkSec 提供两级 WAF 防护能力：

1. **平台自保护（Platform Ingress WAF）**：
   - 内置在 ALinkSec Gateway 容器中，基于 `WafFilter` 和 `WafEngineService`，默认以 `DetectionOnly` 模式评估所有传入 `/api/**` 的请求。
   - 当发现 SQLi、XSS、RCE、LFI 或恶意扫描器时，自动生成 `web_attack` 安全告警并上报至告警中心。
   - 管理员可在控制台或调用 `/api/system/waf/config` 将模式切换为 `On`，此时请求将在网关层被直接 403 阻断。

2. **业务站点代理防护（Reverse Proxy with CRS / Coraza）**：
   - 针对安装有 ALinkSec Agent 的目标主机上运行的 Web 业务（如 Nginx、Tomcat、Node.js 站点），通过在反向代理接入 ModSecurity v3 + OWASP CRS 或 Coraza-SPOA。
   - WAF 审计日志（Audit Log）由 Agent 日志采集器监听，并将攻击事件实时转化为平台安全事件。

---

## 2. 业务 Nginx 反向代理配置 ModSecurity + OWASP CRS

### 步骤 1：安装依赖包
在 Debian/Ubuntu 主机上安装 libmodsecurity3 与 Nginx 动态模块：
```bash
apt-get update && apt-get install -y libmodsecurity3 libnginx-mod-http-modsecurity
```

### 步骤 2：下载并校验 CRS 规则集
使用 ALinkSec 提供的更新脚本下载并校验指定版本的 CRS：
```bash
python3 /opt/alinksec/deploy/update-crs.py --version v4.1.0 --output /etc/nginx/modsec/crs/
```

### 步骤 3：配置 ModSecurity 基础规则 (`/etc/nginx/modsec/modsecurity.conf`)
```apache
# 初始建议开启 DetectionOnly，调优误报后再切为 On
SecRuleEngine DetectionOnly

SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

# 审计日志输出供 ALinkSec Agent 监听
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogFormat JSON
```

### 步骤 4：引入 ALinkSec 专用误报豁免基线 (`EXCLUSION-RULES-BEFORE-CRS.conf`)
```apache
# 豁免静态资源与健康检查
SecRule REQUEST_URI "@beginsWith /healthz" "id:1001,phase:1,pass,nolog,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@rx \.(?:css|js|png|jpg|svg|ico)$" "id:1002,phase:1,pass,nolog,ctl:ruleEngine=Off"

# 豁免上传接口的大字段
SecRule REQUEST_URI "@beginsWith /api/upload" "id:1003,phase:2,pass,nolog,ctl:ruleRemoveById=942100"
```

### 步骤 5：在 Nginx 站点配置中启用
```nginx
server {
    listen 80;
    server_name example.com;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## 3. 日志接入与告警闭环

在 ALinkSec Agent 的日志采集配置中，添加 `/var/log/nginx/modsec_audit.log` 监听：
- 每当 ModSecurity 触发告警时，Agent 解析 JSON 格式日志中的 `transaction.client_ip`、`transaction.request.uri` 与 `messages` 规则 ID。
- Agent 将其封装为 `type: "web_attack"` 的 `RptSecurityEvent` 发往 ALinkSec 服务端。
- 服务端根据配置的**响应规则（D01-D04）**，可自动对恶意攻击源 IP 执行临时封禁（`block_ip`）并在到期后自动解封。

---

## 4. 误报调优与拦截模式上线流程

1. **观察期（1-2 周）**：以 `DetectionOnly` 模式运行，监控日常业务流量产生的告警。
2. **分析排错**：对误报的请求识别具体规则编号（如 942100 SQLi 误报 JSON 属性），编写局部 `ctl:ruleRemoveTargetById` 豁免。
3. **切换拦截**：确认核心业务路径 0 误报后，将 `SecRuleEngine` 修改为 `On`（或通过 ALinkSec API `/api/system/waf/config` 将 `mode` 设置为 `"On"`）。
