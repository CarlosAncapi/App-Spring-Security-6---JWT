package com.app.SpringSecurityApp.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/method")
//@PreAuthorize("denyAll()") // por defecto no dejará pasar a nadie a menos que yo se lo indique, aunque tenga usuario y contraseña
public class testAuthController {

    @GetMapping("/get")
    //@PreAuthorize("hasAnyAuthority('READ')")
    public String helloGet(){
        return "Hello World - GET";
    }

    @PostMapping("/post")
    //@PreAuthorize("hasAnyAuthority('CREATE' or 'READ')")
    public String helloPost(){
        return "Hello World - POST";
    }

    @PutMapping("/put")
    public String helloPut(){
        return "Hello World - PUT";
    }

    @DeleteMapping("/delete")
    public String helloDelete(){
        return "Hello World - DELETE";
    }

    @PatchMapping("/patch")
    //@PreAuthorize("hasAnyAuthority('REFACTOR')")
    public String helloPatch() {
        return "Hello World - PATCH";
    }


}
