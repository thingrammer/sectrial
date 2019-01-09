package com.example.demo.controller

import com.example.demo.UserDetailsServiceImpl
import com.example.demo.provider.Data
import org.apache.catalina.core.ApplicationContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*

@RestController

class HtmlController {
    @Autowired
    lateinit var data: Data

    @GetMapping("/")
    fun index(): Any {
        return "index"

    }

    @GetMapping("/ok")
    fun take(): Any {
//        var principal = SecurityContextHolder.getContext().authentication.principal
//        println(principal)
        return "ok"
    }

    @GetMapping("/auth")
    fun auth(): Any {
        return "no auth"
    }
    @PreAuthorize("hasAuthority('JWT_AUTH')")
    @GetMapping("/ctn")
    fun content(): Any {
        return "content"
    }
    @PreAuthorize("JWT_AUTH")
    @GetMapping("/principal")
    fun principal(): Any {
        return SecurityContextHolder.getContext()
//        return ApplicationContext().getF
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/role-data")
    fun dataWithRole(): Any {
        return "roles"
    }

    @Autowired
    lateinit var userDetailsService: UserDetailsServiceImpl

    @PostMapping("/sign/up")
    fun signUp(@RequestBody user: Map<String, String>): Any {
        userDetailsService.saveUser(user["username"]!!, user["password"]!!)
        return userDetailsService.getUserData()
    }
    @PostMapping("/login")
    fun login(): Any{
        return userDetailsService.getUserData()
    }
    @GetMapping("/user/info")
    fun userInfo(): Any {
        return userDetailsService.getUserData()
    }
}
