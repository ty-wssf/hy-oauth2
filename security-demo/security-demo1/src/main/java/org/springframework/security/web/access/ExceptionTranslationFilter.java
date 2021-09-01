/*
 * Copyright 2004-2016 the original author or authors.
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
package org.springframework.security.web.access;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.ThrowableCauseExtractor;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import org.springframework.context.support.MessageSourceAccessor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles any <code>AccessDeniedException</code> and <code>AuthenticationException</code>
 * thrown within the filter chain.
 * <p>
 * This filter is necessary because it provides the bridge between Java exceptions and
 * HTTP responses. It is solely concerned with maintaining the user interface. This filter
 * does not do any actual security enforcement.
 * <p>
 * If an {@link AuthenticationException} is detected, the filter will launch the
 * <code>authenticationEntryPoint</code>. This allows common handling of authentication
 * failures originating from any subclass of
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor}.
 * <p>
 * If an {@link AccessDeniedException} is detected, the filter will determine whether or
 * not the user is an anonymous user. If they are an anonymous user, the
 * <code>authenticationEntryPoint</code> will be launched. If they are not an anonymous
 * user, the filter will delegate to the
 * {@link org.springframework.security.web.access.AccessDeniedHandler}. By default the
 * filter will use {@link org.springframework.security.web.access.AccessDeniedHandlerImpl}.
 * <p>
 * To use this filter, it is necessary to specify the following properties:
 * <ul>
 * <li><code>authenticationEntryPoint</code> indicates the handler that should commence
 * the authentication process if an <code>AuthenticationException</code> is detected. Note
 * that this may also switch the current protocol from http to https for an SSL login.</li>
 * <li><tt>requestCache</tt> determines the strategy used to save a request during the
 * authentication process in order that it may be retrieved and reused once the user has
 * authenticated. The default implementation is {@link HttpSessionRequestCache}.</li>
 * </ul>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class ExceptionTranslationFilter extends GenericFilterBean {

    // ~ Instance fields
    // ================================================================================================

    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
    private AuthenticationEntryPoint authenticationEntryPoint;
    // 用于判断一个Authentication是否Anonymous,Remember Me,
    // 缺省使用 AuthenticationTrustResolverImpl
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    // 用于分析一个Throwable抛出的原因，使用本类自定义的嵌套类DefaultThrowableAnalyzer，
    // 主要是加入了对ServletException的分析
    private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

    // 请求缓存，缺省使用HttpSessionRequestCache，在遇到异常启动认证过程时会用到,
    // 因为要先把原始请求缓存下来，一旦认证成功结果，需要把原始请求提出重新跳转到相应URL
    private RequestCache requestCache = new HttpSessionRequestCache();

    private final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint) {
        this(authenticationEntryPoint, new HttpSessionRequestCache());
    }

    public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint,
                                      RequestCache requestCache) {
        Assert.notNull(authenticationEntryPoint,
                "authenticationEntryPoint cannot be null");
        Assert.notNull(requestCache, "requestCache cannot be null");
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.requestCache = requestCache;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationEntryPoint,
                "authenticationEntryPoint must be specified");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // 在任何请求到达时不做任何操作，直接放行，继续filter chain的执行，
        // 但是使用一个 try-catch 来捕获filter chain中接下来会发生的各种异常，
        // 重点关注其中的以下异常，其他异常继续向外抛出 :
        // AuthenticationException : 认证失败异常,通常因为认证信息错误导致
        // AccessDeniedException : 访问被拒绝异常，通常因为权限不足导致
        try {
            chain.doFilter(request, response);

            logger.debug("Chain processed normally");
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            // Try to extract a SpringSecurityException from the stacktrace
            Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
            // 检测ex是否由AuthenticationException或者AccessDeniedException异常导致
            RuntimeException ase = (AuthenticationException) throwableAnalyzer
                    .getFirstThrowableOfType(AuthenticationException.class, causeChain);

            if (ase == null) {
                ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(
                        AccessDeniedException.class, causeChain);
            }

            if (ase != null) {
                if (response.isCommitted()) {
                    // 如果response已经提交，则没办法向响应中转换和写入这些异常了，只好抛一个异常
                    throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", ex);
                }
                // 如果ex是由AuthenticationException或者AccessDeniedException异常导致，
                // 并且响应尚未提交，这里将这些Spring Security异常翻译成相应的 http response。
                handleSpringSecurityException(request, response, chain, ase);
            } else {
                // Rethrow ServletExceptions and RuntimeExceptions as-is
                if (ex instanceof ServletException) {
                    throw (ServletException) ex;
                } else if (ex instanceof RuntimeException) {
                    throw (RuntimeException) ex;
                }

                // Wrap other Exceptions. This shouldn't actually happen
                // as we've already covered all the possibilities for doFilter
                throw new RuntimeException(ex);
            }
        }
    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    protected AuthenticationTrustResolver getAuthenticationTrustResolver() {
        return authenticationTrustResolver;
    }

    // 此方法仅用于处理两种Spring Security 异常:
    // AuthenticationException , AccessDeniedException
    private void handleSpringSecurityException(HttpServletRequest request,
                                               HttpServletResponse response, FilterChain chain, RuntimeException exception)
            throws IOException, ServletException {
        if (exception instanceof AuthenticationException) {
            logger.debug(
                    "Authentication exception occurred; redirecting to authentication entry point",
                    exception);

            // 如果是 AuthenticationException 异常，启动认证流程
            sendStartAuthentication(request, response, chain,
                    (AuthenticationException) exception);
        } else if (exception instanceof AccessDeniedException) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authenticationTrustResolver.isAnonymous(authentication) || authenticationTrustResolver.isRememberMe(authentication)) {
                // 如果当前认证token是匿名或者RememberMe token
                logger.debug(
                        "Access is denied (user is " + (authenticationTrustResolver.isAnonymous(authentication) ? "anonymous" : "not fully authenticated") + "); redirecting to authentication entry point",
                        exception);

                // 如果是 AccessDeniedException 异常，而且当前登录主体是匿名状态或者
                // Remember Me认证，则也启动认证流程
                sendStartAuthentication(
                        request,
                        response,
                        chain,
                        new InsufficientAuthenticationException(
                                messages.getMessage(
                                        "ExceptionTranslationFilter.insufficientAuthentication",
                                        "Full authentication is required to access this resource")));
            } else {
                logger.debug(
                        "Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
                        exception);

                // 如果是 AccessDeniedException 异常,而且当前用户不是匿名，也不是
                // Remember Me, 而是真正经过认证的某个用户，则说明是该用户权限不足,
                // 则交给 accessDeniedHandler 处理，缺省告知其权限不足
                // 注意 : 如果当前被请求的页面被配置成RememberMe权限可访问，但实际上
                // 当前当前安全上下文中的token是fullAuthenticated的，则也会走到这个流程
                accessDeniedHandler.handle(request, response,
                        (AccessDeniedException) exception);
            }
        }
    }

    // 发起认证流程
    protected void sendStartAuthentication(HttpServletRequest request,
                                           HttpServletResponse response, FilterChain chain,
                                           AuthenticationException reason) throws ServletException, IOException {
        // SEC-112: Clear the SecurityContextHolder's Authentication, as the
        // existing Authentication is no longer considered valid
        // 将SecurityContextHolder中SecurityContext的authentication设置为null
        SecurityContextHolder.getContext().setAuthentication(null);

        // 保存当前请求，一旦认证成功，认证机制会再次提取该请求并跳转到该请求对应的页面
        requestCache.saveRequest(request, response);

        // 准备工作已经做完，开始认证流程
        logger.debug("Calling Authentication entry point.");
        authenticationEntryPoint.commence(request, response, reason);
    }

    public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
        this.accessDeniedHandler = accessDeniedHandler;
    }

    public void setAuthenticationTrustResolver(
            AuthenticationTrustResolver authenticationTrustResolver) {
        Assert.notNull(authenticationTrustResolver,
                "authenticationTrustResolver must not be null");
        this.authenticationTrustResolver = authenticationTrustResolver;
    }

    public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
        Assert.notNull(throwableAnalyzer, "throwableAnalyzer must not be null");
        this.throwableAnalyzer = throwableAnalyzer;
    }

    /**
     * Default implementation of <code>ThrowableAnalyzer</code> which is capable of also
     * unwrapping <code>ServletException</code>s.
     */
    private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
        /**
         * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
         */
        @Override
        protected void initExtractorMap() {
            super.initExtractorMap();

            registerExtractor(ServletException.class, new ThrowableCauseExtractor() {
                @Override
                public Throwable extractCause(Throwable throwable) {
                    ThrowableAnalyzer.verifyThrowableHierarchy(throwable,
                            ServletException.class);
                    return ((ServletException) throwable).getRootCause();
                }
            });
        }

    }

}
