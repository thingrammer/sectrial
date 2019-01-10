package com.example.auth.jwt.config.security

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
        UriHandler.uris = methods.filter { !it.value.hasMethodAnnotation(JwtAuth::class.java) }
                .map { it.key.patternsCondition.patterns.first()!! }
    }
}

object UriHandler {
    lateinit var uris: List<String>
}