package com.iyestin.demo.cas.spring.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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


}
