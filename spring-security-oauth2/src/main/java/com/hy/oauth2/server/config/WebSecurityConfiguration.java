package com.hy.oauth2.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hy.oauth2.server.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsUtils;

import javax.servlet.http.Cookie;
import java.io.PrintWriter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        // 设置默认的加密方式
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 使用自定义认证与授权
        auth.userDetailsService(userDetailsService());
        // 基于内存存储用户
        /*auth.inMemoryAuthentication()
                // 在内存中创建用户并为密码加密
                .withUser("user").password(passwordEncoder().encode("123456")).roles("USER")
                .and()
                .withUser("admin").password(passwordEncoder().encode("123456")).roles("ADMIN");*/

    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 将 check_token 暴露出去，否则资源服务器访问时报 403 错误
        web.ignoring().antMatchers("/oauth/check_token");
    }

    /**
     * 解决Unsupported grant type: password问题
     * 密码模式依赖认证管理器
     *
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * httpBasic是利用HTTP头部进行认证，访问页面时会由浏览器弹框要求密码，这个是走HTTP协议层面的认证
     * <p>
     * formLogin是基于页面，你需要自己实现一个登录页面，也就是示例中的/usercheck.jsp（名字你可以自己定），
     * 里面要有一个登录表单，表单的action和用户名 密码字段名都是框架定死的，然后你需要再实现一个servlet来处理这个表单的action，实现登录，实际上走的是session/cookie认证
     *
     * @param http
     * @throws Exception
     */
    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/login")
                .and()
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest()
                .authenticated()
                .and().csrf().disable().cors();

    }*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*super.configure(http);
        http
                .logout()
                .permitAll()
                .addLogoutHandler(new CustomLogoutHandler())
                .logoutSuccessHandler(new CustomLogoutSuccessHandler());*/

        // 存在bug，无法退出
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
                .successHandler((req, resp, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                .failureHandler((req, resp, e) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(e.getMessage());
                    out.flush();
                    out.close();
                })
                .permitAll(true)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                            resp.setContentType("application/json;charset=utf-8");
                            PrintWriter out = resp.getWriter();
                            out.write("尚未登录，请先登录");
                            out.flush();
                            out.close();
                        }
                )
                .and()
                .httpBasic()
                .and()
                .logout()
                .permitAll()
                .logoutSuccessHandler((req, resp, authentication) -> {
                    // 将子系统的cookie删掉  实现退出一个系统其他子系统跟着退出
                    Cookie[] cookies = req.getCookies();
                    if (cookies != null && cookies.length > 0) {
                        for (Cookie cookie : cookies) {
                            cookie.setMaxAge(0);
                            cookie.setPath("/");
                            resp.addCookie(cookie);
                        }
                    }
                    /*req.getSession().invalidate();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("注销成功");
                    out.flush();
                    out.close();*/
                });
    }


    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("secret"));
    }

}
