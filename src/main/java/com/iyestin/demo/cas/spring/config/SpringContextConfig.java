package com.iyestin.demo.cas.spring.config;

import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CharacterEncodingFilter;

import java.util.Arrays;

/**
 * Created by yestin on 2016/3/28.
 */
@Configuration
public class SpringContextConfig {

    @Bean
    public CharacterEncodingFilter characterEncodingFilter(){
        return new CharacterEncodingFilter("utf-8");
    }

    @Bean
    public FilterRegistrationBean characterEncodingFilterRegister(){
        FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setFilter(characterEncodingFilter());
        bean.setUrlPatterns(Arrays.asList(new String[]{"/*"}));
        return bean;
    }

}
