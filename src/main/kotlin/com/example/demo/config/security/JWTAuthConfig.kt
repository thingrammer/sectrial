package com.example.demo.config.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm.HMAC512
import com.example.demo.UserDetailsServiceImpl
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.io.IOException
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


data class ApplicationUser(
        var id: Long,
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
                .withExpiresAt(Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.toByteArray()))
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token)
    }
}

class JWTAuthorizationFilter(authManager: AuthenticationManager) : BasicAuthenticationFilter(authManager) {
    override fun doFilterInternal(req: HttpServletRequest,
                                  res: HttpServletResponse,
                                  chain: FilterChain) {
        val header = req.getHeader(HEADER_STRING)

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res)
            return
        }
        val authentication = getAuthentication(req)
        SecurityContextHolder.getContext().authentication = authentication
        chain.doFilter(req, res)
    }

    private fun getAuthentication(request: HttpServletRequest): UsernamePasswordAuthenticationToken? {
        val token = request.getHeader(HEADER_STRING)
        if (token != null) {
            // parse the token.
            val user = JWT.require(HMAC512(SECRET.toByteArray()))
                    .build()
                    .verify(token.replace(TOKEN_PREFIX, ""))
                    .subject

            return if (user != null) {
                UsernamePasswordAuthenticationToken(user, null, ArrayList())
            } else null
        }
        return null
    }
}

const val EXPIRATION_TIME = 1000_00
const val SECRET = "123124"
const val HEADER_STRING = "Authorization"
const val TOKEN_PREFIX = "JWT-"
const val SIGN_UP_URL = "/sign/up"

@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurity(private var userDetailsService: UserDetailsServiceImpl,
                  private var bCryptPasswordEncoder: BCryptPasswordEncoder) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
//                .authorizeRequests().antMatchers("/", "/principal").hasRole("JWT_AUTH")
//                .permitAll()
//                .and()
                .cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, SIGN_UP_URL).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(JWTAuthenticationFilter(authenticationManager()))
                .addFilter(JWTAuthorizationFilter(authenticationManager()))
//                .addFilterBefore(jwtDetectFilter(authenticationManager()), JWTAuthorizationFilter::class.java)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    }

    @Autowired
    fun configureGlobal(auth: AuthenticationManagerBuilder) {

        auth.userDetailsService<UserDetailsService>(userDetailsService).passwordEncoder(bCryptPasswordEncoder)
//        auth.authenticationProvider(JWTRoleProvider())
    }

    @Bean
    internal fun corsConfigurationSource(): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", CorsConfiguration().applyPermitDefaultValues())
        return source
    }
}

class JWTAuthenticationToken : AbstractAuthenticationToken {
    constructor() : super(null)
    constructor(authorities: Collection<GrantedAuthority>) : super(authorities) {
        super.setAuthenticated(true)

    }

    override fun getCredentials(): Any? {
        return ""
    }

    override fun getPrincipal(): Any? {
        return ""
    }

}

class JWTRoleProvider : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        return JWTAuthenticationToken(listOf(SimpleGrantedAuthority("JWT_AUTH")))
    }

    override fun supports(authentication: Class<*>): Boolean {
        return JWTAuthenticationToken::class.java
                .isAssignableFrom(authentication)
    }


}

fun jwtDetectFilter(authenticationManager: AuthenticationManager):
        JWTDetectFilter {
    var jwtDetectFilter = JWTDetectFilter()
    jwtDetectFilter.setAuthenticationManager(authenticationManager)
    return jwtDetectFilter
}


class JWTDetectFilter
internal constructor() : AbstractAuthenticationProcessingFilter("/") {
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        return authenticationManager.authenticate(JWTAuthenticationToken())
    }
}