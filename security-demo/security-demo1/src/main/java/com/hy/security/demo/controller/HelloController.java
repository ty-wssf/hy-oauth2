package com.hy.security.demo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class HelloController {

    @Autowired
    private TestAsyncService testAsyncService;


    @GetMapping("hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/hello1")
    public String hello2(HelloController helloController) {
        log.info("主线程");
        testAsyncService.testSync();
        return "hello";
    }

}