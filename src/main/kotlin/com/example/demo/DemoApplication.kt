package com.example.demo

import com.example.demo.config.security.JwtAuth
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping


@SpringBootApplication
class DemoApplication

@Configuration
class JwtInitConfig {
    @Bean
    fun bCryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
    @Autowired
    fun EndpointDocController(handlerMapping: RequestMappingHandlerMapping) {
        HandlerMapping.handlers = handlerMapping
        var methods = HandlerMapping.handlers.handlerMethods
        for (m in methods) {
            if (!m.value.hasMethodAnnotation(JwtAuth::class.java)) {
                HandlerMapping.urls.add(m.key.patternsCondition.patterns.first()!!)
            }
        }
    }
}

object HandlerMapping {
    lateinit var handlers: RequestMappingHandlerMapping
    var urls: ArrayList<String> = ArrayList()
}

fun main(args: Array<String>) {
    runApplication<DemoApplication>(*args)
}



