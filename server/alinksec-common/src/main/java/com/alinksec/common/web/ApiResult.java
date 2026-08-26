package com.alinksec.common.web;

import com.alinksec.common.error.ErrorCode;

/**
 * REST 统一响应体：{code, msg, data}（code=0 成功，其余对齐 ErrorCode）。
 */
public record ApiResult<T>(int code, String msg, T data) {

    public static <T> ApiResult<T> ok(T data) {
        return new ApiResult<>(0, "ok", data);
    }

    public static ApiResult<Void> ok() {
        return new ApiResult<>(0, "ok", null);
    }

    public static <T> ApiResult<T> error(ErrorCode ec) {
        return new ApiResult<>(ec.code(), ec.message(), null);
    }

    public static <T> ApiResult<T> error(int code, String msg) {
        return new ApiResult<>(code, msg, null);
    }
}
