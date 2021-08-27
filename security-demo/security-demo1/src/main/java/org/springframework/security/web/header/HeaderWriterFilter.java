/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.web.header;

import org.springframework.security.web.util.OnCommittedResponseWrapper;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Filter implementation to add headers to the current response. Can be useful to add
 * certain headers which enable browser protection. Like X-Frame-Options, X-XSS-Protection
 * and X-Content-Type-Options.
 *
 * @author Marten Deinum
 * @author Josh Cummings
 * @since 3.2
 */
public class HeaderWriterFilter extends OncePerRequestFilter {

    /**
     * Collection of  HeaderWriter instances to write out the headers to the
     * response.
     * 将要写入响应头部的头部写入器，注意，这里不是直接提供头部信息让该Filter自己写入响应头部，
     * 而是委托给各个头部写入器HeaderWriter完成，当前Filter并不关心每个头部信息如何写入的细节。
     */
    private final List<HeaderWriter> headerWriters;

    /**
     * Creates a new instance. 构建一个当前Filter的实例，外部提供对响应对象的头部写入器
     *
     * @param headerWriters the  HeaderWriter instances to write out headers to the
     *                      HttpServletResponse.
     */
    public HeaderWriterFilter(List<HeaderWriter> headerWriters) {
        Assert.notEmpty(headerWriters, "headerWriters cannot be null or empty");
        this.headerWriters = headerWriters;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 将传入的response对象和头部写入器放在一起包装成一个HeaderWriterResponse对象，
        // 该HeaderWriterResponse本身带有执行头部写入器的能力(可以被外部主动调用,也可能在响应对象
        // 的某些事件发生时自主调用)，但此时并不执行这些头部写入器，只是将响应对象携带上需要的信息
        // 二次封装继续传递，在需要执行的时候再执行。
        HeaderWriterResponse headerWriterResponse = new HeaderWriterResponse(request,
                response, this.headerWriters);
        HeaderWriterRequest headerWriterRequest = new HeaderWriterRequest(request,
                headerWriterResponse);

        try {
            // 头部写入器已经绑定到二次封装的headerWriterResponse上了，继续filter chain
            // 的执行
            filterChain.doFilter(headerWriterRequest, headerWriterResponse);
        } finally {
            // 逻辑执行到这里，说明请求处理已经完成，已经处于回写响应对象给客户的阶段了，
            // 这里调用头部写入方法。
            // 注意，这里虽然调用头部写入方法，但真正的头部写入动作并不一定真正在这里发生,
            // 因为该动作有可能已经在其他Filter中发生，具体请参考OnCommittedResponseWrapper
            // 赋予HeaderWriterResponse的这种能力。
            headerWriterResponse.writeHeaders();
        }
    }

    // 继承OnCommittedResponseWrapper实现一个自定义的HttpServletResponse，
    // HeaderWriterResponse 实现的核心逻辑是提供一个onResponseCommitted()方法实现，
    // 用于写入要求的头部信息到响应对象。
    // 而onResponseCommitted()会在response被commit前确保被调用，这一点是OnCommittedResponseWrapper
    // 的任务。一般来讲，在处理中发生 include,sendError, redirect, flushBuffer 时会导致 response commit,
    // 而OnCommittedResponseWrapper的设计目的就是就是在这些事件将要发生时，调用onResponseCommitted()。
    static class HeaderWriterResponse extends OnCommittedResponseWrapper {
        private final HttpServletRequest request;
        private final List<HeaderWriter> headerWriters;

        HeaderWriterResponse(HttpServletRequest request, HttpServletResponse response,
                             List<HeaderWriter> headerWriters) {
            super(response);
            this.request = request;
            this.headerWriters = headerWriters;
        }

        /*
         * (non-Javadoc)
         *
         * @see org.springframework.security.web.util.OnCommittedResponseWrapper#
         * onResponseCommitted()
         */
        @Override
        protected void onResponseCommitted() {
            // 将头部信息写入响应对象
            writeHeaders();
            // 一旦完成头部写入，设置一个标记声明这件事情，从而可以避免
            // 对该方法的再次调用或者对writeHeaders()不会导致重复写入
            // 头部信息到响应对象
            this.disableOnResponseCommitted();
        }

        protected void writeHeaders() {
            if (isDisableOnResponseCommitted()) {
                // 先检查是否已经将头部写入响应的标记，如果已经写入则不再二次写入
                return;
            }
            // 将头部写入响应
            for (HeaderWriter headerWriter : this.headerWriters) {
                headerWriter.writeHeaders(this.request, getHttpResponse());
            }
        }

        private HttpServletResponse getHttpResponse() {
            return (HttpServletResponse) getResponse();
        }
    }

    static class HeaderWriterRequest extends HttpServletRequestWrapper {
        private final HeaderWriterResponse response;

        HeaderWriterRequest(HttpServletRequest request, HeaderWriterResponse response) {
            super(request);
            this.response = response;
        }

        @Override
        public RequestDispatcher getRequestDispatcher(String path) {
            return new HeaderWriterRequestDispatcher(super.getRequestDispatcher(path), this.response);
        }
    }

    static class HeaderWriterRequestDispatcher implements RequestDispatcher {
        private final RequestDispatcher delegate;
        private final HeaderWriterResponse response;

        HeaderWriterRequestDispatcher(RequestDispatcher delegate, HeaderWriterResponse response) {
            this.delegate = delegate;
            this.response = response;
        }

        @Override
        public void forward(ServletRequest request, ServletResponse response) throws ServletException, IOException {
            this.delegate.forward(request, response);
        }

        @Override
        public void include(ServletRequest request, ServletResponse response) throws ServletException, IOException {
            this.response.onResponseCommitted();
            this.delegate.include(request, response);
        }
    }
}
