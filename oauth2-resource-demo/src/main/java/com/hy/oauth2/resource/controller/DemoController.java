package com.hy.oauth2.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author wyl
 * @since 2021-08-20 10:57:30
 */
@RestController
@RequestMapping
public class DemoController {

    @RequestMapping("view/1")
    public String list() {
        return "哈哈，终于可以访问了";
    }

    @PreAuthorize("hasAuthority('System')")
    @RequestMapping("/test1")
    public String test1() {
        return "哈哈，终于可以访问了";
    }

    @PreAuthorize("hasRole('ROLE_test2')")
    @RequestMapping("/test2")
    public String test2() {
        return "哈哈，终于可以访问了";
    }

    @RequestMapping("/test3")
    public String test3() {
        return "哈哈，终于可以访问了";
    }

}
