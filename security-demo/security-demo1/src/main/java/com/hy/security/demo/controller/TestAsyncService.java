package com.hy.security.demo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * @author wyl
 * @since 2021-08-27 15:08:32
 */
@Service
@Slf4j
public class TestAsyncService {

    @Async
    public void testSync() {
        log.info("子线程");
        SecurityContextHolder.getContext();
    }

}
