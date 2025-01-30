package com.example.SpringSecurityEx.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String hello(){
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")   // Used for Role Based Access
    @GetMapping("/user")
    public String userEndpoint(){
        return "Hello User!";
    }

    @PreAuthorize("hasRole('ADMIN')")   // Used for Role Based Access
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello Admin!";
    }

}
