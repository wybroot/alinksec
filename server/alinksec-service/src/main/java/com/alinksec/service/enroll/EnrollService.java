package com.alinksec.service.enroll;

import com.alinksec.common.error.ApiException;
import com.alinksec.common.error.ErrorCode;
import com.alinksec.proto.EnrollRequest;
import com.alinksec.proto.EnrollResponse;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.cert.CertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Agent 注册（通信协议 §6）：
 * token 核销 → machine_id 查重 → 签发证书（CN=agent_id）→ 落库 t_agent。
 */
@Service
public class EnrollService {

    private static final Logger log = LoggerFactory.getLogger(EnrollService.class);

    private final EnrollTokenService tokenService;
    private final AgentRepository agentRepository;
    private final CertService certService;

    public EnrollService(EnrollTokenService tokenService, AgentRepository agentRepository,
                         CertService certService) {
        this.tokenService = tokenService;
        this.agentRepository = agentRepository;
        this.certService = certService;
    }

    @Transactional
    public EnrollResponse enroll(EnrollRequest request) {
        if (request.getEnrollToken().isBlank() || !request.hasHost()) {
            throw new ApiException(ErrorCode.INVALID_ARGUMENT);
        }
        tokenService.consume(request.getEnrollToken());

        var host = request.getHost();
        String machineId = host.getMachineId().isBlank() ? null : host.getMachineId();
        if (machineId != null && agentRepository.findByMachineId(machineId).isPresent()) {
            log.warn("重复注册拒绝: machine_id={} hostname={}", machineId, host.getHostname());
            throw new ApiException(ErrorCode.MACHINE_ALREADY_ENROLLED);
        }

        String agentId = UUID.randomUUID().toString();
        CertService.IssuedCert cert;
        try {
            cert = certService.issueClientCert(agentId);
        } catch (Exception e) {
            throw new ApiException(ErrorCode.INTERNAL_ERROR, "签发证书失败");
        }

        String primaryIp = host.getIpListList().isEmpty() ? null : host.getIpList(0);
        agentRepository.insert(new AgentEntity(
                null, agentId, host.getHostname(), primaryIp, (short) host.getOsType().getNumber(),
                host.getOsVersion(), host.getKernel(), host.getArch(), host.getAgentVersion(),
                machineId, null, AgentEntity.STATUS_PENDING, true, null,
                cert.serial(), null, null, null));

        log.info("Agent 注册成功: agent_id={} hostname={} ip={} os={}",
                agentId, host.getHostname(), primaryIp, host.getOsType());

        return EnrollResponse.newBuilder()
                .setAgentId(agentId)
                .setClientCert(com.google.protobuf.ByteString.copyFromUtf8(cert.certPem()))
                .setClientKey(com.google.protobuf.ByteString.copyFromUtf8(cert.keyPem()))
                .setCaCert(pemOfCa())
                .build();
    }

    private String pemOfCa() {
        try {
            var sw = new java.io.StringWriter();
            try (var pem = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {
                pem.writeObject(certService.caCert());
            }
            return sw.toString();
        } catch (Exception e) {
            throw new ApiException(ErrorCode.INTERNAL_ERROR, "读取平台 CA 失败");
        }
    }
}
