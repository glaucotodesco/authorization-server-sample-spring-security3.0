package com.abutua.authorizationserversample.resources;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    
    @GetMapping("${security.login-page}")
    public String login() {
         return "login";
    }

}