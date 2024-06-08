package com.example.demo.controllers;

import com.example.demo.appuser.AppUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class adminController {
    @Autowired
    private AppUserService userService;

    @RequestMapping("/authenti/all")
    public ResponseEntity<?> findAllUsers(){
        return new ResponseEntity<>(userService.findAll(), HttpStatus.OK);
    }


}
