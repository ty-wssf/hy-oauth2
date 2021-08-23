package com.hy.oauth2.resource.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author wyl
 * @date 2019-03-19
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.logout().logoutSuccessUrl("http://localhost:8086/logout");
        http.authorizeRequests().anyRequest().authenticated();
        http.csrf().disable();
    }

}
