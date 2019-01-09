package com.example.demo.controller

import com.example.demo.HandlerMapping
import com.example.demo.config.security.JwtAuth
import com.example.demo.repository.DemoMapper
import com.example.demo.service.impl.UserDetailsServiceImpl
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController


@RestController

class BaseController {
    @Autowired
    lateinit var demoMapper: DemoMapper

    @GetMapping("/")
    fun index(): Any {
        return "index"

    }

    @GetMapping("/ok")
    fun take(): Any {
        return "ok"
    }

    @GetMapping("/auth")
    fun auth(): Any {
        return "no auth"
    }


    @JwtAuth
    @GetMapping("/ctn")
    fun content(): Any {

        return HandlerMapping.urls
    }

    @GetMapping("/principal")
    fun principal(): Any {
        return SecurityContextHolder.getContext()
    }

    @Autowired
    lateinit var userDetailsService: UserDetailsServiceImpl

    @PostMapping("/sign/up")
    fun signUp(@RequestBody user: Map<String, String>): Any {
        userDetailsService.saveUser(user["username"]!!, user["password"]!!)
        return userDetailsService.getUserData()
    }

    @PostMapping("/login")
    fun login() = Unit

    @GetMapping("/user/info")
    fun userInfo(): Any {
        return userDetailsService.getUserData()
    }
}
