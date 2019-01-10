package com.example.demo.config.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping

@Configuration
class JwtInitConfig {
    @Bean
    fun bCryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Autowired
    fun handleMapping(handlerMapping: RequestMappingHandlerMapping) {
        var handlers = handlerMapping
        var methods = handlers.handlerMethods
        for (m in methods) {
            if (!m.value.hasMethodAnnotation(JwtAuth::class.java)) {
                UriHandler.uris.add(m.key.patternsCondition.patterns.first()!!)
            }
        }
    }
}

object UriHandler {
    var uris: ArrayList<String> = ArrayList()
}