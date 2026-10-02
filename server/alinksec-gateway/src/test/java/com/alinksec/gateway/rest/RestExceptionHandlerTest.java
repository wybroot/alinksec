package com.alinksec.gateway.rest;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

class RestExceptionHandlerTest {

    @RestController
    static class UploadController {
        @PostMapping("/upload-limit-test")
        void upload() {
            throw new MaxUploadSizeExceededException(1024);
        }
    }

    @Test
    void reportsUploadLimitAsPayloadTooLarge() throws Exception {
        standaloneSetup(new UploadController()).setControllerAdvice(new RestExceptionHandler()).build()
                .perform(post("/upload-limit-test"))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.msg").value("上传文件超过大小限制"));
    }
}
