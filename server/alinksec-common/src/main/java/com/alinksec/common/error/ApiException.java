package com.alinksec.common.error;

/**
 * 携带平台错误码的业务异常。gRPC 层统一转换为 Status(code, description)。
 */
public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode) {
        super(errorCode.message());
        this.errorCode = errorCode;
    }

    public ApiException(ErrorCode errorCode, String detail) {
        super(errorCode.message() + ": " + detail);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() { return errorCode; }
}
