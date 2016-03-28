package com.iyestin.demo.cas.spring.controller;

import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by yestin on 2016/3/5.
 */
@RestController
public class TestController {

    @RequestMapping("/test")
    public String test(){
        return "hi";
    }

    @RequestMapping("/admin")
    public String admin(){
        return "admin saying hi";
    }

    @RequestMapping("/user")
    public Map<String, Object> userInfo(){
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String,Object> map = new HashMap<String, Object>();
        map.put("isCasAuthentication",true);
        map.put("auths",auth.getAuthorities());
        map.put("details",auth.getDetails());
        map.put("principal",auth.getPrincipal());
        map.put("credentials",auth.getCredentials());
        return map;
    }
}
