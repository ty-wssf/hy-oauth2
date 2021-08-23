package com.hy.security.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.cors.CorsUtils;

/**
 * @author wyl
 * @date 2019-03-19
 */
@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 不配置/login post 403
                .csrf()
                .disable()
                // 跨域
                .cors()
                .and()
                .authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest)
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("http://localhost:9081/login.html")
                .loginProcessingUrl("/login")
                .permitAll(true)
                .and()
                .httpBasic()
                .and();

    }

}
