package com.iyestin.demo.cas.spring.config;

import com.iyestin.demo.cas.spring.security.GrantedAuthorityFromAssertionAttributesUserDetailsService;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.authentication.CachingUserDetailsService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * SecurityConfig
 * Created by lwz on 2016/1/12.
 * spring security configuration
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    SecurityCasConfigProperties casProperties;

    public AuthenticationUserDetailsService authenticationUserDetailsService(){

        GrantedAuthorityFromAssertionAttributesUserDetailsService service =
                new GrantedAuthorityFromAssertionAttributesUserDetailsService(new String[]{"role"});
        return service;
    }

    @Bean
    public ServiceProperties serviceProperties(){
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setSendRenew(false);
//        serviceProperties.setService("http://localhost:8091/login/cas");
        serviceProperties.setService(casProperties.getServiceName());

        serviceProperties.setAuthenticateAllArtifacts(true);
        return serviceProperties;
    }

    @Bean
    public CasAuthenticationFilter casFilter() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());

        filter.setProxyGrantingTicketStorage(proxyGrantingTicketStorage());
        filter.setProxyReceptorUrl("/login/cas/proxyreceptor");

        return filter;
    }

    @Bean
    public CasAuthenticationEntryPoint casEntryPoint(){
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
//        entryPoint.setLoginUrl("http://localhost:8080/cas/login");
        entryPoint.setLoginUrl(casProperties.getCasAddress() + casProperties.getLoginUrl());
        entryPoint.setServiceProperties(serviceProperties());
        return entryPoint;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider(){
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
//        UserDetailsByNameServiceWrapper wrapper = new UserDetailsByNameServiceWrapper(userDetailsService());
//
//        provider.setAuthenticationUserDetailsService(wrapper);

        provider.setAuthenticationUserDetailsService(authenticationUserDetailsService());

        Cas20ProxyTicketValidator validator = new Cas20ProxyTicketValidator(casProperties.getCasAddress());
        validator.setAcceptAnyProxy(true);
        provider.setTicketValidator(validator);

        provider.setKey("test");

        return provider;
    }

    @Bean
    public ServiceAuthenticationDetailsSource authenticationDetailsSource(){
        return new ServiceAuthenticationDetailsSource(serviceProperties());
    }

    @Bean
    public Cas20ServiceTicketValidator ticketValidator(){
        Cas20ServiceTicketValidator tv =  new Cas20ServiceTicketValidator(casProperties.getCasAddress());
        tv.setProxyCallbackUrl(casProperties.getAppAddress() + "/login/cas/proxyreceptor");
        tv.setProxyGrantingTicketStorage(proxyGrantingTicketStorage());
        return tv;
    }



    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        // add cas auth.
        auth.authenticationProvider(casAuthenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 设置不拦截规则
        web.ignoring().antMatchers("/static/**");

    }

    @Bean
    public SingleSignOutFilter singleSignOutFilter(){
        return new SingleSignOutFilter();
    }

    @Bean
    public LogoutFilter requestSingleLogoutFilter(){
        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
        LogoutFilter filter = new LogoutFilter(casProperties.getCasAddress()
                + casProperties.getLogoutUrl(), handler);
        filter.setFilterProcessesUrl("/logout/cas");
        return filter;
    }

    public ProxyGrantingTicketStorage proxyGrantingTicketStorage(){
        return new ProxyGrantingTicketStorageImpl();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilter(casFilter());
        http.addFilterBefore(singleSignOutFilter(), LogoutFilter.class);
        http.addFilterBefore(requestSingleLogoutFilter(), casFilter().getClass());
        http.logout().logoutSuccessUrl("/cas-logout.jsp");

        http.httpBasic().authenticationEntryPoint(casEntryPoint());

        http.csrf().disable();

        http.authorizeRequests().antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated();

    }

}