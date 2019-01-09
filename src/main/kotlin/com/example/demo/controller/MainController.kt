package com.example.demo.controller

import com.example.demo.HandlerMapping
import com.example.demo.UserDetailsServiceImpl
import com.example.demo.config.security.JwtAuth
import com.example.demo.provider.Data
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.support.DefaultListableBeanFactory
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.*
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.stereotype.Component


@RestController

class HtmlController {
    @Autowired
    lateinit var data: Data

    @GetMapping("/")
    fun index(): Any {
        val beansWithAnnotation = DefaultListableBeanFactory().getBeansWithAnnotation(Controller::class.java)


        return beansWithAnnotation

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
    fun login(): Any? {
//        return SecurityContextHolder.getContext()
        var res = displayAllBeans()
        System.err.println("????")
        System.err.println(res)
        return res

    }

    fun findTarget() {

    }

    @Autowired
    lateinit var applicationContext: ApplicationContext

    fun displayAllBeans() {
        val controllerBeans = applicationContext!!.getBeansWithAnnotation(RestController::class.java)
        for (bean in controllerBeans) {
            println(bean::class.java.name)
        }
    }

    @GetMapping("/user/info")
    fun userInfo(): Any {
        return userDetailsService.getUserData()
    }

    @Autowired
    lateinit var ctx: ApplicationContextProvider


}

@Component
class ApplicationContextProvider : ApplicationContextAware {

    override fun setApplicationContext(p0: org.springframework.context.ApplicationContext) {
        this.context = p0
    }

    var context: ApplicationContext? = null
}