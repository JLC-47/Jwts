package com.jwt.auth.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.jwt.auth.filter.JwtValidationFilter;

@Configuration
public class FilterConfig {
    @Bean
    FilterRegistrationBean<JwtValidationFilter> jwtFilter(JwtValidationFilter jwtValidationFilter) {
        
        FilterRegistrationBean<JwtValidationFilter> registrationBean = new FilterRegistrationBean<>();

        
        registrationBean.setFilter(jwtValidationFilter);

        
        registrationBean.addUrlPatterns("/*");

        
        registrationBean.setOrder(1);

        
        return registrationBean;
    }

}
