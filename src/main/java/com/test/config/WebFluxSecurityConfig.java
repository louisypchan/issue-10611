package com.test.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.CustomHttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import static org.springframework.security.config.web.server.CustomHttpSecurity.http;


/****************************************************************************
 Copyright (c) 2017 Louis Y P Chen.
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 ****************************************************************************/
@Configuration
@EnableWebFluxSecurity
public class WebFluxSecurityConfig {

    /**
     * Copy from HttpSecurityConfiguration
     * @return
     */
    @Autowired(required = false)
    private ReactiveAuthenticationManager authenticationManager;

    /**
     * Copy from HttpSecurityConfiguration
     * @return
     */
    @Autowired(required = false)
    private UserDetailsRepository userDetailsRepository;

    /**
     * Copy from HttpSecurityConfiguration
     * @return
     */
    @Autowired(required = false)
    private PasswordEncoder passwordEncoder;

   @Bean("bbddbear")
   @Scope("prototype")
   public CustomHttpSecurity httpSecurity() {
       return http()
               .authenticationManager(authenticationManager())
               .headers().and()
               .httpBasic().and()
               .formLogin().and()
               .logout().and();
   }

    @Bean
    SecurityWebFilterChain withAuthentication(CustomHttpSecurity http) throws Exception {
        String[] patterns = {"/demo/**"};
        return http.httpBasic().and().securityMatcher(ServerWebExchangeMatchers.pathMatchers(patterns))
                .authorizeExchange().pathMatchers(patterns).authenticated().and().build();
    }

    /**
     * Copy from HttpSecurityConfiguration
     * @return
     */
    private ReactiveAuthenticationManager authenticationManager() {
        if(this.authenticationManager != null) {
            return this.authenticationManager;
        }
        if(this.userDetailsRepository != null) {
            UserDetailsRepositoryAuthenticationManager manager =
                    new UserDetailsRepositoryAuthenticationManager(this.userDetailsRepository);
            if(this.passwordEncoder != null) {
                manager.setPasswordEncoder(this.passwordEncoder);
            }
            return manager;
        }
        return null;
    }
}
