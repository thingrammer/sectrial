package com.demo.jwt.config.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.stereotype.Component
import java.io.IOException
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "jwt")
object JwtProperties {
    var EXPIRATION_TIME = 1000_000_0000
    var SECRET = "123124"
    var HEADER_STRING = "Authorization"
    var TOKEN_PREFIX = "JWT-"
    var SIGN_UP_URL = "/sign/up"
}

data class ApplicationUser(
        var id: Long, // not used
        var username: String,
        var password: String
)

class JWTAuthenticationFilter(var authManager: AuthenticationManager) : UsernamePasswordAuthenticationFilter() {
    override fun attemptAuthentication(req: HttpServletRequest,
                                       res: HttpServletResponse?): Authentication {
        try {
            val creds = jacksonObjectMapper()
                    .readValue(req.inputStream, ApplicationUser::class.java)
            return authManager.authenticate(
                    UsernamePasswordAuthenticationToken(
                            creds.username,
                            creds.password,
                            ArrayList<GrantedAuthority>())
            )
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    override fun successfulAuthentication(req: HttpServletRequest,
                                          res: HttpServletResponse,
                                          chain: FilterChain,
                                          auth: Authentication) {

        val token = JWT.create()
                .withSubject((auth.principal as User).username)
                .withExpiresAt(Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JwtProperties.SECRET.toByteArray()))
        res.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + token)
    }
}

class JWTAuthorizationFilter(authManager: AuthenticationManager) : BasicAuthenticationFilter(authManager) {
    override fun doFilterInternal(req: HttpServletRequest,
                                  res: HttpServletResponse,
                                  chain: FilterChain) {
        val header = req.getHeader(JwtProperties.HEADER_STRING)

        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(req, res)
            return
        }
        val authentication = getAuthentication(req)
        SecurityContextHolder.getContext().authentication = authentication
        chain.doFilter(req, res)
    }

    private fun getAuthentication(request: HttpServletRequest): UsernamePasswordAuthenticationToken? {
        val token = request.getHeader(JwtProperties.HEADER_STRING)
        if (token != null) {
            // parse the token.
            val user = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET.toByteArray()))
                    .build()
                    .verify(token.replace(JwtProperties.TOKEN_PREFIX, ""))
                    .subject

            return if (user != null) {
                UsernamePasswordAuthenticationToken(user, null, emptyList())
            } else null
        }
        return null
    }
}


