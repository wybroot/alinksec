package com.alinksec.gateway.rest;

import com.alinksec.common.error.ApiException;
import com.alinksec.common.error.ErrorCode;
import com.alinksec.common.web.ApiResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * REST 全局异常 → 统一 ApiResult。
 */
@RestControllerAdvice
public class RestExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(RestExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ApiResult<Void> handleApi(ApiException e) {
        return ApiResult.error(e.getErrorCode().code(), e.getMessage());
    }

    @ExceptionHandler({MissingServletRequestParameterException.class,
            IllegalArgumentException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResult<Void> handleBadRequest(Exception e) {
        return ApiResult.error(ErrorCode.INVALID_ARGUMENT.code(), e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResult<Void> handleOther(Exception e) {
        log.error("REST 处理异常", e);
        return ApiResult.error(ErrorCode.INTERNAL_ERROR.code(), "服务内部错误");
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    public ApiResult<Void> handleUploadLimit(MaxUploadSizeExceededException e) {
        return ApiResult.error(ErrorCode.INVALID_ARGUMENT.code(), "上传文件超过大小限制");
    }
}
