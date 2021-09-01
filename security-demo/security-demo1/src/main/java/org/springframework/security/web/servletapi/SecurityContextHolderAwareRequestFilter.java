/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.servletapi;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * A <code>Filter</code> which populates the <code>ServletRequest</code> with a request
 * wrapper which implements the servlet API security methods.
 * <p>
 * In pre servlet 3 environment the wrapper class used is
 * {@link SecurityContextHolderAwareRequestWrapper}. See its javadoc for the methods that
 * are implemented.
 * </p>
 * <p>
 * In a servlet 3 environment {@link SecurityContextHolderAwareRequestWrapper} is extended
 * to provide the following additional methods:
 * </p>
 * <ul>
 * <li>{@link HttpServletRequest#authenticate(HttpServletResponse)} - Allows the user to
 * determine if they are authenticated and if not send the user to the login page. See
 * {@link #setAuthenticationEntryPoint(AuthenticationEntryPoint)}.</li>
 * <li>{@link HttpServletRequest#login(String, String)} - Allows the user to authenticate
 * using the {@link AuthenticationManager}. See
 * {@link #setAuthenticationManager(AuthenticationManager)}.</li>
 * <li>{@link HttpServletRequest#logout()} - Allows the user to logout using the
 * {@link LogoutHandler}s configured in Spring Security. See
 * {@link #setLogoutHandlers(List)}.</li>
 * <li>{@link AsyncContext#start(Runnable)} - Automatically copy the
 * {@link SecurityContext} from the {@link SecurityContextHolder} found on the Thread that
 * invoked {@link AsyncContext#start(Runnable)} to the Thread that processes the
 * {@link Runnable}.</li>
 * </ul>
 *
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 * @author Eddú Meléndez
 */
public class SecurityContextHolderAwareRequestFilter extends GenericFilterBean {
    // ~ Instance fields
    // ================================================================================================

    // 缺省角色名称的前缀
    private String rolePrefix = "ROLE_";

    // 用于封装HttpServletRequest的工厂类，最终目的是封装HttpServletRequest
    // 使之具有访问SecurityContextHolder中安全上下文的能力。
    // 针对 Servlet 2.5 和 Servlet 3 使用的不同实现类。
    private HttpServletRequestFactory requestFactory;

    private AuthenticationEntryPoint authenticationEntryPoint;

    private AuthenticationManager authenticationManager;

    private List<LogoutHandler> logoutHandlers;

    // 判断认证对象Authentication是何种类型:是否匿名Authentication,
    // 是否 Remember Me Authentication。
    // 缺省使用实现AuthenticationTrustResolverImpl,
    // 根据对象Authentication所使用的实现类是AnonymousAuthenticationToken
    // 还是RememberMeAuthenticationToken达到上述目的
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    // ~ Methods
    // ========================================================================================================
    // 指定角色前缀，
    public void setRolePrefix(String rolePrefix) {
        Assert.notNull(rolePrefix, "Role prefix must not be null");
        this.rolePrefix = rolePrefix;
        // 角色前缀变更时更新requestFactory工厂
        updateFactory();
    }

    /**
     * <p>
     * Sets the {@link AuthenticationEntryPoint} used when integrating
     * {@link HttpServletRequest} with Servlet 3 APIs. Specifically, it will be used when
     * {@link HttpServletRequest#authenticate(HttpServletResponse)} is called and the user
     * is not authenticated.
     * </p>
     * <p>
     * If the value is null (default), then the default container behavior will be be
     * retained when invoking {@link HttpServletRequest#authenticate(HttpServletResponse)}
     * .
     * </p>
     *
     * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use when
     *                                 invoking {@link HttpServletRequest#authenticate(HttpServletResponse)} if the user
     *                                 is not authenticated.
     * @throws IllegalStateException if the Servlet 3 APIs are not found on the classpath
     */
    public void setAuthenticationEntryPoint(
            AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /**
     * <p>
     * Sets the {@link AuthenticationManager} used when integrating
     * {@link HttpServletRequest} with Servlet 3 APIs. Specifically, it will be used when
     * {@link HttpServletRequest#login(String, String)} is invoked to determine if the
     * user is authenticated.
     * </p>
     * <p>
     * If the value is null (default), then the default container behavior will be
     * retained when invoking {@link HttpServletRequest#login(String, String)}.
     * </p>
     *
     * @param authenticationManager the {@link AuthenticationManager} to use when invoking
     *                              {@link HttpServletRequest#login(String, String)}
     * @throws IllegalStateException if the Servlet 3 APIs are not found on the classpath
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * <p>
     * Sets the {@link LogoutHandler}s used when integrating with
     * {@link HttpServletRequest} with Servlet 3 APIs. Specifically it will be used when
     * {@link HttpServletRequest#logout()} is invoked in order to log the user out. So
     * long as the {@link LogoutHandler}s do not commit the {@link HttpServletResponse}
     * (expected), then the user is in charge of handling the response.
     * </p>
     * <p>
     * If the value is null (default), the default container behavior will be retained
     * when invoking {@link HttpServletRequest#logout()}.
     * </p>
     *
     * @param logoutHandlers the {@code List&lt;LogoutHandler&gt;}s when invoking
     *                       {@link HttpServletRequest#logout()}.
     * @throws IllegalStateException if the Servlet 3 APIs are not found on the classpath
     */
    public void setLogoutHandlers(List<LogoutHandler> logoutHandlers) {
        this.logoutHandlers = logoutHandlers;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(this.requestFactory.create((HttpServletRequest) req,
                (HttpServletResponse) res), res);
    }

    @Override
    public void afterPropertiesSet() throws ServletException {
        // 本Filter因为继承自GenericFilterBean，从而隐含地实现了接口InitializingBean，
        // 所以会有此方法。而此方法会在该Filter bean被初始化时调用。此时会确定具体使用的
        // requestFactory 实例
        super.afterPropertiesSet();
        updateFactory();
    }

    private void updateFactory() {
        // 更新封装HttpServletRequest的工厂实例requestFactory，
        // 根据当前使用的Servlet版本的不同使用不同的工厂类
        String rolePrefix = this.rolePrefix;
        this.requestFactory = isServlet3() ? createServlet3Factory(rolePrefix)
                : new HttpServlet25RequestFactory(this.trustResolver, rolePrefix);
    }

    /**
     * Sets the {@link AuthenticationTrustResolver} to be used. The default is
     * {@link AuthenticationTrustResolverImpl}.
     *
     * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
     *                      null.
     */
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        Assert.notNull(trustResolver, "trustResolver cannot be null");
        this.trustResolver = trustResolver;
        // trustResolver 变更时更新requestFactory工厂
        updateFactory();
    }

    private HttpServletRequestFactory createServlet3Factory(String rolePrefix) {
        HttpServlet3RequestFactory factory = new HttpServlet3RequestFactory(rolePrefix);
        factory.setTrustResolver(this.trustResolver);
        factory.setAuthenticationEntryPoint(this.authenticationEntryPoint);
        factory.setAuthenticationManager(this.authenticationManager);
        factory.setLogoutHandlers(this.logoutHandlers);
        return factory;
    }

    /**
     * Returns true if the Servlet 3 APIs are detected.
     *
     * @return
     */
    private boolean isServlet3() {
        return ClassUtils.hasMethod(ServletRequest.class, "startAsync");
    }
}
