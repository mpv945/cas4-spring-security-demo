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

    public AuthenticationUserDetailsService authenticationUserDetailsService(){

        GrantedAuthorityFromAssertionAttributesUserDetailsService service =
                new GrantedAuthorityFromAssertionAttributesUserDetailsService(new String[]{"role"});
        return service;
    }

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetailsService detailsService = new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
                return new UserDetails() {
                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        GrantedAuthority authority = new GrantedAuthority() {
                            @Override
                            public String getAuthority() {
                                return "ROLE_TEST";
                            }
                        };
                        List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
                        list.add(authority);
                        return list;
                    }

                    @Override
                    public String getPassword() {
                        return null;
                    }

                    @Override
                    public String getUsername() {
                        return username;
                    }

                    @Override
                    public boolean isAccountNonExpired() {
                        return true;
                    }

                    @Override
                    public boolean isAccountNonLocked() {
                        return true;
                    }

                    @Override
                    public boolean isCredentialsNonExpired() {
                        return true;
                    }

                    @Override
                    public boolean isEnabled() {
                        return true;
                    }
                };
            }
        };
        return detailsService;
    }

    @Bean
    public ServiceProperties serviceProperties(){
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setSendRenew(false);
        serviceProperties.setService("http://localhost:8090/login/cas");

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
        entryPoint.setLoginUrl("http://localhost:8080/cas/login");
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

        Cas20ProxyTicketValidator validator = new Cas20ProxyTicketValidator("http://localhost:8080/cas");
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
        Cas20ServiceTicketValidator tv =  new Cas20ServiceTicketValidator("http://localhost:8080/cas");
        tv.setProxyCallbackUrl("http://localhost:8090/login/cas/proxyreceptor");
        tv.setProxyGrantingTicketStorage(proxyGrantingTicketStorage());
        return tv;
    }



    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        // add cas auth.
        auth.authenticationProvider(casAuthenticationProvider());

//        auth.userDetailsService(userDetailsService());
//        //指定密码加密所使用的加密器为passwordEncoder()
//        // 需要将密码加密后写入数据库
//        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
//        //不删除凭据，以便记住用户
//        auth.eraseCredentials(false);
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
        LogoutFilter filter = new LogoutFilter("http://localhost:8080/cas/logout", handler);
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

//        http.authorizeRequests().antMatchers("/**").hasRole("USER")
//                .anyRequest().authenticated();

//        //设置拦截规则
//        http.authorizeRequests()
//                .antMatchers("/admin/**").hasRole("ADMIN")//只有管理员可访问页面
//                .anyRequest().authenticated();
//
//        //自定义登录界面
//        http.csrf().disable().formLogin().loginPage("/login")
//                .loginProcessingUrl("/logon")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login?error")
//                .permitAll();
//        // 自定义注销
//        http.logout().logoutUrl("/logout")
//                .logoutSuccessUrl("/login?logout")//注销回到登录页面并且提示登出
//                .permitAll()
//                .deleteCookies("JSESSIONID")
//                .deleteCookies("remember-me")
//                .invalidateHttpSession(true);
//
//        //session管理
//        http.sessionManagement()
//                .sessionFixation().changeSessionId()
//                .maximumSessions(10).maxSessionsPreventsLogin(false).expiredUrl("/login?expired");
//
//        //remember-me配置
//        http.rememberMe().tokenValiditySeconds(360000).tokenRepository(tokenRepository());
    }


//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder(4);
//    }
//
//    @Bean
//    public JdbcTokenRepositoryImpl tokenRepository() {
//        JdbcTokenRepositoryImpl j = new JdbcTokenRepositoryImpl();
//        j.setDataSource(dataSource);
//        return j;
//    }
//
//    @Bean
//    public SavedRequestAwareAuthenticationSuccessHandler loginSuccessHandler() {
//        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
//        handler.setDefaultTargetUrl("/");
//        //handler.setRequestCache();
//        return handler;
//    }
}