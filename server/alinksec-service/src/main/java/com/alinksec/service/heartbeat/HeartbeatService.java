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

    public HeartbeatService(AgentRepository agentRepository, CommandService commandService,
                            AlinkSecProperties props, PolicyStoreService policyStore,
                            VirusDbService virusDbService) {
        this.agentRepository = agentRepository;
        this.commandService = commandService;
        this.props = props;
        this.policyStore = policyStore;
        this.virusDbService = virusDbService;
    }

    public void onHeartbeat(String agentId, RptHeartbeat hb) {
        agentRepository.heartbeat(agentId, hb.getAgentVersion(), hb.getPolicyVersion());

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
    @Scheduled(fixedDelay = 30_000, initialDelay = 60_000)
    public void markOfflineAgents() {
        List<AgentEntity> stale = agentRepository.findStaleOnline(OFFLINE_SECONDS);
        for (AgentEntity agent : stale) {
            agentRepository.updateStatus(agent.agentId(), AgentEntity.STATUS_OFFLINE);
            log.warn("主机离线: agent={} hostname={} last_heartbeat={}",
                    agent.agentId(), agent.hostname(), agent.lastHeartbeat());
        }
    }
}
