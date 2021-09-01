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

package org.springframework.security.web.access.intercept;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;

import javax.servlet.*;
import java.io.IOException;

/**
 * Performs security handling of HTTP resources via a filter implementation.
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of
 * type {@link FilterInvocationSecurityMetadataSource}.
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements
        Filter {
    // ~ Static fields/initializers
    // =====================================================================================

    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

    // ~ Instance fields
    // ================================================================================================

    private FilterInvocationSecurityMetadataSource securityMetadataSource;
    private boolean observeOncePerRequest = true;

    // ~ Methods
    // ========================================================================================================

    /**
     * Not used (we rely on IoC container lifecycle services instead)
     *
     * @param arg0 ignored
     * @throws ServletException never thrown
     */
    @Override
    public void init(FilterConfig arg0) throws ServletException {
    }

    /**
     * Not used (we rely on IoC container lifecycle services instead)
     */
    @Override
    public void destroy() {
    }

    /**
     * Method that is actually called by the filter chain. Simply delegates to the
     * {@link #invoke(FilterInvocation)} method.
     *
     * @param request  the servlet request
     * @param response the servlet response
     * @param chain    the filter chain
     * @throws IOException      if the filter chain fails
     * @throws ServletException if the filter chain fails
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        // 封装请求上下文为一个FilterInvocation,然后调用该FilterInvocation执行安全认证
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        invoke(fi);
    }

    public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource newSource) {
        this.securityMetadataSource = newSource;
    }

    @Override
    public Class<?> getSecureObjectClass() {
        return FilterInvocation.class;
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if ((fi.getRequest() != null)
                && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && observeOncePerRequest) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            // 如果被指定为在整个请求处理过程中只能执行最多一次 ,并且监测到已经执行过,
            // 则直接放行，继续 filter chain 的执行
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null && observeOncePerRequest) {
                // 如果被指定为在整个请求处理过程中只能执行最多一次 ,并且监测到尚未执行,
                // 则设置已经执行标志，随后执行职责逻辑
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            // 这里是该过滤器进行安全检查的职责逻辑,具体实现在基类AbstractSecurityInterceptor
            // 主要是进行必要的认证和授权检查，如果遇到相关异常则抛出异常，之后的过滤器链
            // 调用不会继续进行
            InterceptorStatusToken token = super.beforeInvocation(fi);

            try {
                // 如果上面通过安全检查，这里继续过滤器的执行
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, null);
        }
    }

    // 指定是否在整个请求处理过程中该过滤器只被执行一次，缺省是 true。
    // 也存在在整个请求处理过程中该过滤器需要执行多次的情况，比如JSP foward/include
    // 等情况。
    public boolean isObserveOncePerRequest() {
        return observeOncePerRequest;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }
}
