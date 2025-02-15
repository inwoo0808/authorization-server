package org.oauth.oauth2.controller;

import org.oauth.oauth2.dto.RegisterClientDto;
import org.oauth.oauth2.dto.RegisterUserDto;
import org.oauth.oauth2.entity.RegisterEntity;
import org.oauth.oauth2.entity.User;
import org.oauth.oauth2.security.CustomRegisteredClientRepository;
import org.oauth.oauth2.service.RegisterClientService;
import org.oauth.oauth2.service.UserService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Controller
public class MainController {

    private final UserService userService;
    private final RegisterClientService registerClientService;

    private final CustomRegisteredClientRepository r;

    public MainController(UserService userService, RegisterClientService registerClientService, CustomRegisteredClientRepository r){
        this.userService = userService;
        this.registerClientService = registerClientService;
        this.r = r;
    }

    @GetMapping("/login")
    public String loginView() {
        return "login";
    }

    @GetMapping("/register")
    public String registerView(){
        return "register";
    }

    @PostMapping("/register")
    @ResponseBody
    public String registerProc(@ModelAttribute RegisterUserDto dto){
        User u = userService.registerUser(dto);
        if (u!=null) {
            return "ok";
        }
        return "error";
    }

    @GetMapping("/")
    @ResponseBody
    public String m(Principal p){
        return "hello";
    }

    @GetMapping("/registerClient")
    public String registerClientView(){
        return "registerClient";
    }

    @PostMapping("/registerClient")
    @ResponseBody
    public RegisterEntity registerClient(@ModelAttribute RegisterClientDto dto){
        return  registerClientService.register(dto);
    }

    @GetMapping("/test/{param}")
    @ResponseBody
    public RegisteredClient test(@PathVariable("param") String param){
        System.out.println(param);
        return r.findByClientId(param);
    }
}
