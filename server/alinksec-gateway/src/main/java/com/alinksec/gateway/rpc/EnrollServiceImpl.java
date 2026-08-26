package com.alinksec.gateway.rpc;

import com.alinksec.common.error.ApiException;
import com.alinksec.common.error.ErrorCode;
import com.alinksec.proto.EnrollRequest;
import com.alinksec.proto.EnrollResponse;
import com.alinksec.proto.EnrollServiceGrpc;
import com.alinksec.service.enroll.EnrollService;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 注册入口：token 认证（协议设计 §6）。错误码语义见 ErrorCode 2xxxx 段。
 */
@Service
public class EnrollServiceImpl extends EnrollServiceGrpc.EnrollServiceImplBase {

    private static final Logger log = LoggerFactory.getLogger(EnrollServiceImpl.class);

    private final EnrollService enrollService;

    public EnrollServiceImpl(EnrollService enrollService) {
        this.enrollService = enrollService;
    }

    @Override
    public void enroll(EnrollRequest request, StreamObserver<EnrollResponse> responseObserver) {
        try {
            EnrollResponse response = enrollService.enroll(request);
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (ApiException e) {
            log.warn("注册拒绝: code={} msg={}", e.getErrorCode().code(), e.getMessage());
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription(e.getErrorCode().code() + " " + e.getMessage())
                    .asRuntimeException());
        } catch (Exception e) {
            log.error("注册内部错误", e);
            responseObserver.onError(Status.INTERNAL
                    .withDescription(ErrorCode.INTERNAL_ERROR.code() + " " + ErrorCode.INTERNAL_ERROR.message())
                    .asRuntimeException());
        }
    }
}
