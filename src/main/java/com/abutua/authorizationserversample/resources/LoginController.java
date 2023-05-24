package com.abutua.authorizationserversample.resources;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class LoginController {

    @GetMapping("/mylogin")
    public String login() {
         return "login";
    }

    @GetMapping("/login")
    public String login2() {
        System.out.println("asdadsadsadsad");
         return "login";
    }
    
}