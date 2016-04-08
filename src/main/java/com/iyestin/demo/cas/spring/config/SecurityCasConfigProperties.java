package com.iyestin.demo.cas.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Created by yestin on 2016/4/8.
 */
@Configuration
@ConfigurationProperties(prefix = "security.cas")
public class SecurityCasConfigProperties {


    /**
     * Service name.
     */
    private String serviceName;

    /**
     * This app deploy address.
     */
    private String appAddress="http://localhost";

    /**
     * CAS Server address.
     */
    private String casAddress = "http://localhost:8080/cas";

    /**
     * the CAS login url.
     */
    private String loginUrl = "/login";

    /**
     * the CAS logout url.
     */
    private String logoutUrl = "/logout";

    /**
     * Proxy ticket validator key
     */
    private String ticketValidatorKey = "key";

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getCasAddress() {
        return casAddress;
    }

    public void setCasAddress(String casAddress) {
        this.casAddress = casAddress;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public String getTicketValidatorKey() {
        return ticketValidatorKey;
    }

    public void setTicketValidatorKey(String ticketValidatorKey) {
        this.ticketValidatorKey = ticketValidatorKey;
    }

    public String getAppAddress() {
        return appAddress;
    }

    public void setAppAddress(String appAddress) {
        this.appAddress = appAddress;
    }
}
