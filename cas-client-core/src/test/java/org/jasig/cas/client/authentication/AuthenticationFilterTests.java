/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.cas.client.authentication;

import junit.framework.TestCase;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

/**
 * Tests for the AuthenticationFilter.
 *
 * @author Scott Battaglia
 * @version $Revision: 11753 $ $Date: 2007-01-03 13:37:26 -0500 (Wed, 03 Jan 2007) $
 * @since 3.0
 */
public final class AuthenticationFilterTests extends TestCase {

    private static final String SERVER_NAME = "localhost:8443";

    private static final String CAS_SERVICE_URL = "https://" + SERVER_NAME + "/service";

    private static final String CAS_LOGIN_URL = "https://" + SERVER_NAME + "/cas/login";

    private AuthenticationFilter filter;

    private FilterChain filterChain;

    protected void setUp() throws Exception {
        // TODO CAS_SERVICE_URL, false, CAS_LOGIN_URL
        this.filter = new AuthenticationFilter();
        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("service", CAS_SERVICE_URL);
        this.filter.init(config);
        this.filterChain = new FilterChain() {
            public void doFilter(ServletRequest arg0, ServletResponse arg1)
                    throws IOException, ServletException {
                // nothing to do
            }
        };
    }

    protected void tearDown() throws Exception {
        this.filter.destroy();
    }

    public void testRedirect() throws Exception {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        request.setSession(session);
        this.filter.doFilter(request, response, this.filterChain);

        assertEquals(CAS_LOGIN_URL + "?service="
                + URLEncoder.encode(CAS_SERVICE_URL, "UTF-8"), response
                .getRedirectedUrl());
    }

    public void testRedirectWithQueryString() throws Exception {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.setQueryString("test=12456");
        request.setRequestURI("/test");
        request.setSecure(true);

        request.setSession(session);
        this.filter = new AuthenticationFilter();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);

        assertEquals(CAS_LOGIN_URL
                + "?service="
                + URLEncoder.encode("https://" + SERVER_NAME
                + request.getRequestURI() + "?" + request.getQueryString(),
                "UTF-8"), response.getRedirectedUrl());
    }

    public void testAssertion() throws Exception {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        request.setSession(session);
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION,
                new AssertionImpl("test"));
        this.filter.doFilter(request, response, this.filterChain);

        assertNull(response.getRedirectedUrl());
    }

    public void testRenew() throws Exception {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        this.filter.setRenew(true);
        request.setSession(session);
        this.filter.doFilter(request, response, this.filterChain);

        assertNotNull(response.getRedirectedUrl());
        assertTrue(response.getRedirectedUrl().indexOf("renew=true") != -1);
    }

    public void testGateway() throws Exception {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        request.setSession(session);
        this.filter.setRenew(true);
        this.filter.setGateway(true);
        this.filter.doFilter(request, response, this.filterChain);
        assertNotNull(session.getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY));
        assertNotNull(response.getRedirectedUrl());

        final MockHttpServletResponse response2 = new MockHttpServletResponse();
        this.filter.doFilter(request, response2, this.filterChain);
        assertNull(session.getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY));
        assertNull(response2.getRedirectedUrl());
    }

    /**
     * Create an assertion for a remembered user.
     * @param attributeName the name of the rememeber-me attribute.
     * 
     * @return A remembered assertion
     */
    private Assertion createRememberMeAssertion(String attributeName) {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put(attributeName, "true");
        final AttributePrincipal principal = new AttributePrincipalImpl("test", attributes);
        return new AssertionImpl(principal);
    }

    /**
     * The user is remembered, the onlyFullyAuthenticated flag is false (default) -> the user accesses.
     *
     * @throws Exception
     */
    public void testRmeUserRmeNotFully() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");

        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION,
                createRememberMeAssertion(AuthenticationFilter.DEFAULT_REMEMBERME_ATTRIBUTE_NAME));
        request.setSession(session);

        final MockHttpServletResponse response = new MockHttpServletResponse();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);
        assertNull(response.getRedirectedUrl());
    }

    /**
     * The user is remembered, the onlyFullyAuthenticated flag is true -> redirection to CAS server login page with renew=true.
     *
     * @throws Exception
     */
    public void testRmeUserRmeFully() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");

        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION,
                createRememberMeAssertion(AuthenticationFilter.DEFAULT_REMEMBERME_ATTRIBUTE_NAME));

        request.setSession(session);

        final MockHttpServletResponse response = new MockHttpServletResponse();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        config.addInitParameter("onlyFullyAuthenticated", "true");
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);
        assertEquals(CAS_LOGIN_URL
                + "?service="
                + URLEncoder.encode("http://" + SERVER_NAME + request.getRequestURI(), "UTF-8")
                + "&renew=true",
                response.getRedirectedUrl());
    }

    /**
     * The user is remembered (specific attribute name), the onlyFullyAuthenticated flag is true,
     * the remember-me attribute name is set to the same specific value -> redirection to CAS server login page with renew=true.
     *
     * @throws Exception
     */
    public void testRmeUserRmeFullySpecificRmeAttributeName() throws Exception {
    	final String RME_ATTRIBUTE_NAME = "newRmeAttributeName";
    	
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");

        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION, createRememberMeAssertion(RME_ATTRIBUTE_NAME));
        request.setSession(session);

        final MockHttpServletResponse response = new MockHttpServletResponse();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        config.addInitParameter("onlyFullyAuthenticated", "true");
        config.addInitParameter("rememberMeAttributeName", RME_ATTRIBUTE_NAME);
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);
        assertEquals(CAS_LOGIN_URL
                + "?service="
                + URLEncoder.encode("http://" + SERVER_NAME + request.getRequestURI(), "UTF-8")
                + "&renew=true",
                response.getRedirectedUrl());
    }
    
    /**
     * The user is authenticated, the onlyFullyAuthenticated flag is false (default) -> the user accesses.
     *
     * @throws Exception
     */
    public void testRmeUserAuthNotFully() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");

        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION, new AssertionImpl("test"));
        request.setSession(session);

        final MockHttpServletResponse response = new MockHttpServletResponse();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);
        assertNull(response.getRedirectedUrl());
    }

    /**
     * The user is authenticated, the onlyFullyAuthenticated flag is true -> the user accesses.
     *
     * @throws Exception
     */
    public void testRmeUserAuthFully() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");

        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(AbstractCasFilter.CONST_CAS_ASSERTION, new AssertionImpl("test"));
        request.setSession(session);

        final MockHttpServletResponse response = new MockHttpServletResponse();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        config.addInitParameter("onlyFullyAuthenticated", "true");
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);
        assertNull(response.getRedirectedUrl());
    }

    /**
     * The user is anonymous, the onlyFullyAuthenticated flag is true -> redirection to CAS server login page.
     *
     * @throws Exception
     */
    public void testRmeUserAnonymousFully() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");

        final MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        final MockHttpServletResponse response = new MockHttpServletResponse();

        final MockFilterConfig config = new MockFilterConfig();
        config.addInitParameter("casServerLoginUrl", CAS_LOGIN_URL);
        config.addInitParameter("serverName", SERVER_NAME);
        config.addInitParameter("onlyFullyAuthenticated", "true");
        this.filter.init(config);

        this.filter.doFilter(request, response, this.filterChain);
        assertEquals(CAS_LOGIN_URL
                + "?service="
                + URLEncoder.encode("http://" + SERVER_NAME + request.getRequestURI(), "UTF-8"),
                response.getRedirectedUrl());
    }
}
