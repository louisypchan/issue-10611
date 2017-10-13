package org.springframework.security.config.web.server;

import com.test.ext.CustomHttpBasicAuthenticationConverter;
import com.test.ext.CustomHttpBasicAuthenticationEntryPoint;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.web.server.*;
import org.springframework.security.web.server.authentication.*;
import org.springframework.security.web.server.authentication.logout.LogoutHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextRepositoryLogoutHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.*;
import org.springframework.security.web.server.header.*;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/**
 * Due to class HttpSecurity can't be extended, so make a copy from HttpSecurity
 */
public class CustomHttpSecurity {
    private ServerWebExchangeMatcher securityMatcher = ServerWebExchangeMatchers.anyExchange();

    private CustomHttpSecurity.AuthorizeExchangeBuilder authorizeExchangeBuilder;

    private CustomHttpSecurity.HeaderBuilder headers;

    private CustomHttpSecurity.HttpBasicBuilder httpBasic;

    private CustomHttpSecurity.FormLoginBuilder formLogin;

    private CustomHttpSecurity.LogoutBuilder logout;

    private ReactiveAuthenticationManager authenticationManager;

    private SecurityContextRepository securityContextRepository;

    private AuthenticationEntryPoint authenticationEntryPoint;

    private List<DelegatingAuthenticationEntryPoint.DelegateEntry> defaultEntryPoints = new ArrayList<>();

    private List<WebFilter> webFilters = new ArrayList<>();

    /**
     * The ServerExchangeMatcher that determines which requests apply to this CustomHttpSecurity instance.
     *
     * @param matcher the ServerExchangeMatcher that determines which requests apply to this CustomHttpSecurity instance.
     *                Default is all requests.
     */
    public CustomHttpSecurity securityMatcher(ServerWebExchangeMatcher matcher) {
        Assert.notNull(matcher, "matcher cannot be null");
        this.securityMatcher = matcher;
        return this;
    }

    public CustomHttpSecurity addFilterAt(WebFilter webFilter, SecurityWebFiltersOrder order) {
        this.webFilters.add(new CustomHttpSecurity.OrderedWebFilter(webFilter, order.getOrder()));
        return this;
    }

    /**
     * Gets the ServerExchangeMatcher that determines which requests apply to this CustomHttpSecurity instance.
     * @return the ServerExchangeMatcher that determines which requests apply to this CustomHttpSecurity instance.
     */
    private ServerWebExchangeMatcher getSecurityMatcher() {
        return this.securityMatcher;
    }

    public CustomHttpSecurity securityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
        return this;
    }

    public CustomHttpSecurity.HttpBasicBuilder httpBasic() {
        if(this.httpBasic == null) {
            this.httpBasic = new CustomHttpSecurity.HttpBasicBuilder();
        }
        return this.httpBasic;
    }

    public CustomHttpSecurity.FormLoginBuilder formLogin() {
        if(this.formLogin == null) {
            this.formLogin = new CustomHttpSecurity.FormLoginBuilder();
        }
        return this.formLogin;
    }

    public CustomHttpSecurity.HeaderBuilder headers() {
        if(this.headers == null) {
            this.headers = new CustomHttpSecurity.HeaderBuilder();
        }
        return this.headers;
    }

    public CustomHttpSecurity.AuthorizeExchangeBuilder authorizeExchange() {
        if(this.authorizeExchangeBuilder == null) {
            this.authorizeExchangeBuilder = new CustomHttpSecurity.AuthorizeExchangeBuilder();
        }
        return this.authorizeExchangeBuilder;
    }

    public CustomHttpSecurity.LogoutBuilder logout() {
        if (this.logout == null) {
            this.logout = new CustomHttpSecurity.LogoutBuilder();
        }
        return this.logout;
    }

    public CustomHttpSecurity authenticationManager(ReactiveAuthenticationManager manager) {
        this.authenticationManager = manager;
        return this;
    }

    public SecurityWebFilterChain build() {
        if(this.headers != null) {
            this.headers.configure(this);
        }
        WebFilter securityContextRepositoryWebFilter = securityContextRepositoryWebFilter();
        if(securityContextRepositoryWebFilter != null) {
            this.webFilters.add(securityContextRepositoryWebFilter);
        }
        if(this.httpBasic != null) {
            this.httpBasic.authenticationManager(this.authenticationManager);
            if(this.securityContextRepository != null) {
                this.httpBasic.securityContextRepository(this.securityContextRepository);
            }
            this.httpBasic.configure(this);
        }
        if(this.formLogin != null) {
            this.formLogin.authenticationManager(this.authenticationManager);
            if(this.securityContextRepository != null) {
                this.formLogin.securityContextRepository(this.securityContextRepository);
            }
            if(this.formLogin.authenticationEntryPoint == null) {
                this.webFilters.add(new CustomHttpSecurity.OrderedWebFilter(new LoginPageGeneratingWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING.getOrder()));
            }
            this.formLogin.configure(this);
        }
        if(this.logout != null) {
            this.logout.configure(this);
        }
        this.addFilterAt(new AuthenticationReactorContextFilter(), SecurityWebFiltersOrder.AUTHENTICATION_CONTEXT);
        if(this.authorizeExchangeBuilder != null) {
            AuthenticationEntryPoint authenticationEntryPoint = getAuthenticationEntryPoint();
            ExceptionTranslationWebFilter exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
            if(authenticationEntryPoint != null) {
                exceptionTranslationWebFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
            }
            this.addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
            this.authorizeExchangeBuilder.configure(this);
        }
        AnnotationAwareOrderComparator.sort(this.webFilters);
        return new MatcherSecurityWebFilterChain(getSecurityMatcher(), this.webFilters);
    }

    private AuthenticationEntryPoint getAuthenticationEntryPoint() {
        if(this.authenticationEntryPoint != null || this.defaultEntryPoints.isEmpty()) {
            return this.authenticationEntryPoint;
        }
        if(this.defaultEntryPoints.size() == 1) {
            return this.defaultEntryPoints.get(0).getEntryPoint();
        }
        DelegatingAuthenticationEntryPoint result = new DelegatingAuthenticationEntryPoint(this.defaultEntryPoints);
        result.setDefaultEntryPoint(this.defaultEntryPoints.get(this.defaultEntryPoints.size() - 1).getEntryPoint());
        return result;
    }

    public static CustomHttpSecurity http() {
        return new CustomHttpSecurity();
    }

    private WebFilter securityContextRepositoryWebFilter() {
        SecurityContextRepository repository = this.securityContextRepository;
        if(repository == null) {
            return null;
        }
        WebFilter result = new SecurityContextRepositoryWebFilter(repository);
        return new CustomHttpSecurity.OrderedWebFilter(result, SecurityWebFiltersOrder.SECURITY_CONTEXT_REPOSITORY.getOrder());
    }

    private CustomHttpSecurity() {}

    /**
     * @author Rob Winch
     * @since 5.0
     */
    public class AuthorizeExchangeBuilder extends AbstractServerWebExchangeMatcherRegistry<CustomHttpSecurity.AuthorizeExchangeBuilder.Access> {
        private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager.builder();
        private ServerWebExchangeMatcher matcher;
        private boolean anyExchangeRegistered;

        public CustomHttpSecurity and() {
            return CustomHttpSecurity.this;
        }

        @Override
        public CustomHttpSecurity.AuthorizeExchangeBuilder.Access anyExchange() {
            CustomHttpSecurity.AuthorizeExchangeBuilder.Access result = super.anyExchange();
            this.anyExchangeRegistered = true;
            return result;
        }

        @Override
        protected CustomHttpSecurity.AuthorizeExchangeBuilder.Access registerMatcher(ServerWebExchangeMatcher matcher) {
            if(this.anyExchangeRegistered) {
                throw new IllegalStateException("Cannot register " + matcher + " which would be unreachable because anyExchange() has already been registered.");
            }
            if(this.matcher != null) {
                throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
            }
            this.matcher = matcher;
            return new CustomHttpSecurity.AuthorizeExchangeBuilder.Access();
        }

        protected void configure(CustomHttpSecurity http) {
            if(this.matcher != null) {
                throw new IllegalStateException("The matcher " + this.matcher + " does not have an access rule defined");
            }
            AuthorizationWebFilter result = new AuthorizationWebFilter(this.managerBldr.build());
            http.addFilterAt(result, SecurityWebFiltersOrder.AUTHORIZATION);
        }

        public final class Access {

            public CustomHttpSecurity.AuthorizeExchangeBuilder permitAll() {
                return access( (a,e) -> Mono.just(new AuthorizationDecision(true)));
            }

            public CustomHttpSecurity.AuthorizeExchangeBuilder denyAll() {
                return access( (a,e) -> Mono.just(new AuthorizationDecision(false)));
            }

            public CustomHttpSecurity.AuthorizeExchangeBuilder hasRole(String role) {
                return access(AuthorityAuthorizationManager.hasRole(role));
            }

            public CustomHttpSecurity.AuthorizeExchangeBuilder hasAuthority(String authority) {
                return access(AuthorityAuthorizationManager.hasAuthority(authority));
            }

            public CustomHttpSecurity.AuthorizeExchangeBuilder authenticated() {
                return access(AuthenticatedAuthorizationManager.authenticated());
            }

            public CustomHttpSecurity.AuthorizeExchangeBuilder access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
                CustomHttpSecurity.AuthorizeExchangeBuilder.this.managerBldr
                        .add(new ServerWebExchangeMatcherEntry<>(
                                CustomHttpSecurity.AuthorizeExchangeBuilder.this.matcher, manager));
                CustomHttpSecurity.AuthorizeExchangeBuilder.this.matcher = null;
                return CustomHttpSecurity.AuthorizeExchangeBuilder.this;
            }
        }
    }

    /**
     * @author Rob Winch
     * @since 5.0
     */
    public class HttpBasicBuilder {
        private ReactiveAuthenticationManager authenticationManager;

        private SecurityContextRepository securityContextRepository = new ServerWebExchangeAttributeSecurityContextRepository();

        private AuthenticationEntryPoint entryPoint = new CustomHttpBasicAuthenticationEntryPoint();

        public CustomHttpSecurity.HttpBasicBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
            return this;
        }

        public CustomHttpSecurity.HttpBasicBuilder securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return this;
        }

        public CustomHttpSecurity and() {
            return CustomHttpSecurity.this;
        }

        public CustomHttpSecurity disable() {
            CustomHttpSecurity.this.httpBasic = null;
            return CustomHttpSecurity.this;
        }

        protected void configure(CustomHttpSecurity http) {
            MediaTypeServerWebExchangeMatcher restMatcher = new MediaTypeServerWebExchangeMatcher(
                    MediaType.APPLICATION_ATOM_XML,
                    MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
                    MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML,
                    MediaType.MULTIPART_FORM_DATA, MediaType.TEXT_XML);
            restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
            CustomHttpSecurity.this.defaultEntryPoints.add(new DelegatingAuthenticationEntryPoint.DelegateEntry(restMatcher, this.entryPoint));
            AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
                    this.authenticationManager);
            authenticationFilter.setAuthenticationFailureHandler(new AuthenticationEntryPointFailureHandler(this.entryPoint));
            authenticationFilter.setAuthenticationConverter(new CustomHttpBasicAuthenticationConverter());
            if(this.securityContextRepository != null) {
                authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
            }
            http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);
        }

        private HttpBasicBuilder() {}
    }

    /**
     * @author Rob Winch
     * @since 5.0
     */
    public class FormLoginBuilder {
        private ReactiveAuthenticationManager authenticationManager;

        private SecurityContextRepository securityContextRepository = new WebSessionSecurityContextRepository();

        private AuthenticationEntryPoint authenticationEntryPoint;

        private ServerWebExchangeMatcher requiresAuthenticationMatcher;

        private AuthenticationFailureHandler authenticationFailureHandler;

        public CustomHttpSecurity.FormLoginBuilder authenticationManager(ReactiveAuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
            return this;
        }

        public CustomHttpSecurity.FormLoginBuilder loginPage(String loginPage) {
            this.authenticationEntryPoint =  new RedirectAuthenticationEntryPoint(loginPage);
            this.requiresAuthenticationMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, loginPage);
            this.authenticationFailureHandler = new AuthenticationEntryPointFailureHandler(new RedirectAuthenticationEntryPoint(loginPage + "?error"));
            return this;
        }

        public CustomHttpSecurity.FormLoginBuilder authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
            this.authenticationEntryPoint = authenticationEntryPoint;
            return this;
        }

        public CustomHttpSecurity.FormLoginBuilder requiresAuthenticationMatcher(ServerWebExchangeMatcher requiresAuthenticationMatcher) {
            this.requiresAuthenticationMatcher = requiresAuthenticationMatcher;
            return this;
        }

        public CustomHttpSecurity.FormLoginBuilder authenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
            this.authenticationFailureHandler = authenticationFailureHandler;
            return this;
        }

        public CustomHttpSecurity.FormLoginBuilder securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return this;
        }

        public CustomHttpSecurity and() {
            return CustomHttpSecurity.this;
        }

        public CustomHttpSecurity disable() {
            CustomHttpSecurity.this.formLogin = null;
            return CustomHttpSecurity.this;
        }

        protected void configure(CustomHttpSecurity http) {
            if(this.authenticationEntryPoint == null) {
                loginPage("/login");
            }
            MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(
                    MediaType.TEXT_HTML);
            htmlMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
            CustomHttpSecurity.this.defaultEntryPoints.add(0, new DelegatingAuthenticationEntryPoint.DelegateEntry(htmlMatcher, this.authenticationEntryPoint));
            AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
                    this.authenticationManager);
            authenticationFilter.setRequiresAuthenticationMatcher(this.requiresAuthenticationMatcher);
            authenticationFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
            authenticationFilter.setAuthenticationConverter(new FormLoginAuthenticationConverter());
            authenticationFilter.setAuthenticationSuccessHandler(new RedirectAuthenticationSuccessHandler("/"));
            authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
            http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.FORM_LOGIN);
        }

        private FormLoginBuilder() {
        }
    }

    /**
     * @author Rob Winch
     * @since 5.0
     */
    public class HeaderBuilder {
        private final List<HttpHeadersWriter> writers;

        private CacheControlHttpHeadersWriter cacheControl = new CacheControlHttpHeadersWriter();

        private ContentTypeOptionsHttpHeadersWriter contentTypeOptions = new ContentTypeOptionsHttpHeadersWriter();

        private StrictTransportSecurityHttpHeadersWriter hsts = new StrictTransportSecurityHttpHeadersWriter();

        private XFrameOptionsHttpHeadersWriter frameOptions = new XFrameOptionsHttpHeadersWriter();

        private XXssProtectionHttpHeadersWriter xss = new XXssProtectionHttpHeadersWriter();

        public CustomHttpSecurity and() {
            return CustomHttpSecurity.this;
        }

        public CustomHttpSecurity.HeaderBuilder.CacheSpec cache() {
            return new CustomHttpSecurity.HeaderBuilder.CacheSpec();
        }

        public CustomHttpSecurity.HeaderBuilder.ContentTypeOptionsSpec contentTypeOptions() {
            return new CustomHttpSecurity.HeaderBuilder.ContentTypeOptionsSpec();
        }

        public CustomHttpSecurity.HeaderBuilder.FrameOptionsSpec frameOptions() {
            return new CustomHttpSecurity.HeaderBuilder.FrameOptionsSpec();
        }

        public CustomHttpSecurity.HeaderBuilder.HstsSpec hsts() {
            return new CustomHttpSecurity.HeaderBuilder.HstsSpec();
        }

        protected void configure(CustomHttpSecurity http) {
            HttpHeadersWriter writer = new CompositeHttpHeadersWriter(this.writers);
            HttpHeaderWriterWebFilter result = new HttpHeaderWriterWebFilter(writer);
            http.addFilterAt(result, SecurityWebFiltersOrder.HTTP_HEADERS_WRITER);
        }

        public CustomHttpSecurity.HeaderBuilder.XssProtectionSpec xssProtection() {
            return new CustomHttpSecurity.HeaderBuilder.XssProtectionSpec();
        }

        public class CacheSpec {
            public void disable() {
                CustomHttpSecurity.HeaderBuilder.this.writers.remove(CustomHttpSecurity.HeaderBuilder.this.cacheControl);
            }

            private CacheSpec() {}
        }

        public class ContentTypeOptionsSpec {
            public void disable() {
                CustomHttpSecurity.HeaderBuilder.this.writers.remove(CustomHttpSecurity.HeaderBuilder.this.contentTypeOptions);
            }

            private ContentTypeOptionsSpec() {}
        }

        public class FrameOptionsSpec {
            public void mode(XFrameOptionsHttpHeadersWriter.Mode mode) {
                CustomHttpSecurity.HeaderBuilder.this.frameOptions.setMode(mode);
            }
            public void disable() {
                CustomHttpSecurity.HeaderBuilder.this.writers.remove(CustomHttpSecurity.HeaderBuilder.this.frameOptions);
            }

            private FrameOptionsSpec() {}
        }

        public class HstsSpec {
            public void maxAge(Duration maxAge) {
                CustomHttpSecurity.HeaderBuilder.this.hsts.setMaxAge(maxAge);
            }

            public void includeSubdomains(boolean includeSubDomains) {
                CustomHttpSecurity.HeaderBuilder.this.hsts.setIncludeSubDomains(includeSubDomains);
            }

            public void disable() {
                CustomHttpSecurity.HeaderBuilder.this.writers.remove(CustomHttpSecurity.HeaderBuilder.this.hsts);
            }

            private HstsSpec() {}
        }

        public class XssProtectionSpec {
            public void disable() {
                CustomHttpSecurity.HeaderBuilder.this.writers.remove(CustomHttpSecurity.HeaderBuilder.this.xss);
            }

            private XssProtectionSpec() {}
        }

        private HeaderBuilder() {
            this.writers = new ArrayList<>(
                    Arrays.asList(this.cacheControl, this.contentTypeOptions, this.hsts,
                            this.frameOptions, this.xss));
        }
    }

    /**
     * @author Shazin Sadakath
     * @since 5.0
     */
    public final class LogoutBuilder {

        private LogoutHandler logoutHandler = new SecurityContextRepositoryLogoutHandler();

        private String logoutUrl = "/logout";

        private ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers
                .pathMatchers(this.logoutUrl);

        public CustomHttpSecurity.LogoutBuilder logoutHandler(LogoutHandler logoutHandler) {
            Assert.notNull(logoutHandler, "logoutHandler must not be null");
            this.logoutHandler = logoutHandler;
            return this;
        }

        public CustomHttpSecurity.LogoutBuilder logoutUrl(String logoutUrl) {
            Assert.notNull(this.logoutHandler, "logoutUrl must not be null");
            this.logoutUrl = logoutUrl;
            this.requiresLogout = ServerWebExchangeMatchers.pathMatchers(logoutUrl);
            return this;
        }

        public CustomHttpSecurity disable() {
            CustomHttpSecurity.this.logout = null;
            return and();
        }

        public CustomHttpSecurity and() {
            return CustomHttpSecurity.this;
        }

        public void configure(CustomHttpSecurity http) {
            LogoutWebFilter logoutWebFilter = createLogoutWebFilter(http);
            http.addFilterAt(logoutWebFilter, SecurityWebFiltersOrder.LOGOUT);
        }

        private LogoutWebFilter createLogoutWebFilter(CustomHttpSecurity http) {
            LogoutWebFilter logoutWebFilter = new LogoutWebFilter();
            logoutWebFilter.setLogoutHandler(this.logoutHandler);
            logoutWebFilter.setRequiresLogout(this.requiresLogout);

            return logoutWebFilter;
        }

        private LogoutBuilder() {}
    }

    private static class OrderedWebFilter implements WebFilter, Ordered {
        private final WebFilter webFilter;
        private final int order;

        public OrderedWebFilter(WebFilter webFilter, int order) {
            this.webFilter = webFilter;
            this.order = order;
        }

        @Override
        public Mono<Void> filter(ServerWebExchange exchange,
                                 WebFilterChain chain) {
            return this.webFilter.filter(exchange, chain);
        }

        @Override
        public int getOrder() {
            return this.order;
        }

        @Override
        public String toString() {
            return "OrderedWebFilter{" + "webFilter=" + this.webFilter + ", order=" + this.order
                    + '}';
        }
    }
}
