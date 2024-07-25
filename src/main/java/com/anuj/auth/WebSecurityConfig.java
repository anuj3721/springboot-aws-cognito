package com.anuj.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class WebSecurityConfig {

    @Value("${cognito.jwks.url}")
    private String jwksUrl;

    @Autowired
    JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        String SWAGGER_UI_ENDPOINT_PATTERN = "/swagger-ui/**";
        String API_DOCS_ENDPOINT_PATTERN = "/v3/api-docs/**";
        String HEALTH_CHECK_API = "/healthCheck";

        List<String> patternsToBypass = new ArrayList<>(List.of(SWAGGER_UI_ENDPOINT_PATTERN));
        patternsToBypass.addAll(List.of(API_DOCS_ENDPOINT_PATTERN, HEALTH_CHECK_API));

        http.cors()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers(patternsToBypass.toArray(new String[0]))
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // required else in case of not valid
                // authentication object in security context returns only http code in response
                // without any
                // specific message
                // basically the default error response from spring boot for unauthorized was not that descriptive
                // so, jwtAuthenticationEntryPoint is a custom error message handler
                .and()
                .addFilterBefore(new JWTAuthorizationFilter(jwksUrl), BasicAuthenticationFilter.class);

        return http.build();
    }
}