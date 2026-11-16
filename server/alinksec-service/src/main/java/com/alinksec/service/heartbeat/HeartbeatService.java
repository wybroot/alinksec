package com.alinksec.service.heartbeat;

import com.alinksec.proto.RptHeartbeat;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.protect.PolicyStoreService;
import com.alinksec.service.virus.VirusDbService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

/**
 * 心跳处理（通信协议 §5）：
 * - 刷新在线状态（M2：并行写 Redis agent:online:{id}，TTL 60s）；
 * - 心跳携带的 policy_version 落后于平台当前版本 → 下发 CmdPolicySync；
 * - 心跳携带的 db_version 落后于平台特征库当前版本 → 下发 CmdSignatureUpdate（docs/05 §1.2）。
 */
@Service
public class HeartbeatService {

    private static final Logger log = LoggerFactory.getLogger(HeartbeatService.class);

    /** 连续 3 个心跳周期无心跳 → 判定离线（M1：30s 扫描，doc 阈值 60s 留裕量） */
    public static final int OFFLINE_SECONDS = 60;

    private final AgentRepository agentRepository;
    private final CommandService commandService;
    private final AlinkSecProperties props;
    private final PolicyStoreService policyStore;
    private final VirusDbService virusDbService;
    private final com.alinksec.service.protect.WindowsLoginService windowsLogin;
    private final com.alinksec.service.protect.FileWatchService fileWatch;
    private final com.alinksec.service.virus.ClamavService clamav;
    private final com.alinksec.service.virus.YaraService yara;
    private final JdbcTemplate jdbc;
    @org.springframework.beans.factory.annotation.Autowired
    private com.alinksec.service.alert.SecurityEventService securityEvents;

    public HeartbeatService(AgentRepository agentRepository, CommandService commandService,
                            AlinkSecProperties props, PolicyStoreService policyStore,
                            VirusDbService virusDbService, com.alinksec.service.protect.WindowsLoginService windowsLogin,
                            com.alinksec.service.protect.FileWatchService fileWatch, com.alinksec.service.virus.ClamavService clamav, com.alinksec.service.virus.YaraService yara, JdbcTemplate jdbc) {
        this.agentRepository = agentRepository;
        this.commandService = commandService;
        this.props = props;
        this.policyStore = policyStore;
        this.virusDbService = virusDbService;
        this.windowsLogin = windowsLogin;
        this.fileWatch = fileWatch;
        this.clamav = clamav;
        this.yara = yara;
        this.jdbc = jdbc;
    }

    @org.springframework.transaction.annotation.Transactional
    public void onHeartbeat(String agentId, RptHeartbeat hb) {
        var previous=agentRepository.findByAgentId(agentId);
        if(agentRepository.heartbeat(agentId, hb.getAgentVersion(), hb.getPolicyVersion())!=1)
            throw new SecurityException("agent_disabled_or_deleted");
        if(previous.isPresent() && previous.get().status()==2)
            jdbc.update("UPDATE t_alert SET status=2,handle_remark='主机已恢复在线',handled_at=CURRENT_TIMESTAMP WHERE agent_id=? AND event_type='host_offline' AND status IN (0,1)",agentId);
        agentRepository.virusContract(agentId,hb.getVirusExecutionContract(),hb.getDbVersion());
        agentRepository.signatureUpdateContract(agentId,hb.getSignatureUpdateContract());
        agentRepository.upgradeContract(agentId,hb.getUpgradeContract());
        agentRepository.isolationContract(agentId,hb.getIsolationContract());
        agentRepository.weakPasswordContract(agentId,hb.getWeakPasswordContract());
        agentRepository.windowsUpdateContract(agentId,hb.getWindowsUpdateContract());
        agentRepository.evidenceContract(agentId,hb.getEvidenceContract());

        windowsLogin.heartbeat(agentId,hb);
        fileWatch.heartbeat(agentId,hb);
        clamav.heartbeat(agentId,hb);
        yara.heartbeat(agentId,hb);
        com.alinksec.service.baseline.ScapReadiness.heartbeat(jdbc,agentId,hb);

        String current = policyStore.currentVersion();
        if (!current.equals(hb.getPolicyVersion())) {
            log.info("策略版本落后，下发同步: agent={} agent_version={} current={}",
                    agentId, hb.getPolicyVersion(), current);
            commandService.dispatchPolicySync(agentId, current, policyStore.contentJson());
        }
        // 特征库版本比对（未装/落后均触发；Agent 幂等，版本一致 ACK DONE）
        virusDbService.pushIfOutdated(agentId, hb.getDbVersion());
    }

    /** 离线扫描：在线但心跳超时的主机置离线（M2 补平台级 offline 告警） */
    @org.springframework.transaction.annotation.Transactional
    @Scheduled(fixedDelay = 30_000, initialDelay = 60_000)
    public void markOfflineAgents() {
        jdbc.update("UPDATE t_agent SET status=2 WHERE deleted=FALSE AND status=1 AND maintenance_until>? AND last_heartbeat<?",System.currentTimeMillis()/1000,new com.alinksec.service.config.DatabaseDialect(props).timestampBefore(java.time.Duration.ofSeconds(OFFLINE_SECONDS)));
        List<AgentEntity> stale = agentRepository.findStaleOnline(OFFLINE_SECONDS);
        for (AgentEntity agent : stale) {
            if(agentRepository.markOfflineIfStale(agent.agentId(),OFFLINE_SECONDS)==1) {
                securityEvents.onEvent(agent.agentId(),com.alinksec.proto.RptSecurityEvent.newBuilder().setRuleId("PLATFORM-HOST-OFFLINE").setRuleName("主机心跳超时").setType("host_offline").setSeverity(com.alinksec.proto.Severity.SEV_HIGH).setActionTaken("alert_only").setDetail(com.alinksec.common.util.JsonUtils.write(java.util.Map.of("lastHeartbeat",String.valueOf(agent.lastHeartbeat()),"thresholdSeconds",OFFLINE_SECONDS))).build());
                log.warn("主机离线: agent={} hostname={} last_heartbeat={}",
                    agent.agentId(), agent.hostname(), agent.lastHeartbeat());
            }
        }
    }
}
