package com.hy.security.demo.config;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * todo
 *
 * @author wyl
 * @since 2021-08-27 11:48:35
 */
@Component
@Order(-1000)
public class DemoFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println(000);
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
