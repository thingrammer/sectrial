package com.example.demo.config.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.PostConstruct
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


//@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig : WebSecurityConfigurerAdapter() {
//    @Bean
//    fun ipAuthenticationProvider(): IpAuthenticationProvider {
//        return IpAuthenticationProvider()
//    }

    fun ipAuthenticationProcessingFilter(authenticationManager: AuthenticationManager):
            IpAuthenticationProcessingFilter {
        var ipAuthenticationProcessingFilter = IpAuthenticationProcessingFilter()
        ipAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager)
        ipAuthenticationProcessingFilter.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/ip?error"))
        return ipAuthenticationProcessingFilter
    }

    @Bean
    fun loginUrlAuthenticationEntryPoint(): LoginUrlAuthenticationEntryPoint {
        var loginUrlAuthenticationEntryPoint = LoginUrlAuthenticationEntryPoint("/auth")
        return loginUrlAuthenticationEntryPoint

    }

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
                .antMatchers("/", "/principal").permitAll()
                .antMatchers("/auth").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutSuccessUrl("/")
                .permitAll()
                .and()
                .exceptionHandling()
                .accessDeniedPage("/auth")
                .authenticationEntryPoint(loginUrlAuthenticationEntryPoint())
//                .formLogin()
//                .permitAll()
//                .and()
//                .logout()
//                .permitAll()
        http.addFilterBefore(
                ipAuthenticationProcessingFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter::class.java)

    }

    @Autowired
    fun configureGlobal(auth: AuthenticationManagerBuilder) {
//        auth.inMemoryAuthentication(). //
//                passwordEncoder(BCryptPasswordEncoder()). //
//                withUser("admin"). //
//                password(BCryptPasswordEncoder(). //
//                        encode("admin")). //
//                roles("USER")
        auth.authenticationProvider(IpAuthenticationProvider())
    }

    @PostConstruct
    fun run() {
//        var principal = SecurityContextHolder.getContext().authentication.principal
//        System.err.println(principal)
    }

}

class IpAuthenticationToken : AbstractAuthenticationToken {

    var ip: String? = null

    constructor(ip: String) : super(null) {
        this.ip = ip
        super.setAuthenticated(false)
    }

    constructor(ip: String, authorities: Collection<GrantedAuthority>) : super(authorities) {
        this.ip = ip
        super.setAuthenticated(true)

    }

    override fun getCredentials(): Any? {
        return null
    }

    override fun getPrincipal(): Any? {
        return this.ip
    }

}

class IpAuthenticationProcessingFilter
internal constructor() : AbstractAuthenticationProcessingFilter(AntPathRequestMatcher("/ip")) {
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        val host = request.remoteHost
        return authenticationManager.authenticate(IpAuthenticationToken(host))
    }
}

class IpAuthenticationProvider : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication? {
        val ipAuthenticationToken = authentication as IpAuthenticationToken
        val ip = ipAuthenticationToken.ip
        val simpleGrantedAuthority = ipAuthorityMap[ip]
        return if (simpleGrantedAuthority == null) {
            null
        } else {
            IpAuthenticationToken(ip!!, listOf(simpleGrantedAuthority))
        }
    }

    //只支持IpAuthenticationToken该身份
    override fun supports(authentication: Class<*>): Boolean {
        return IpAuthenticationToken::class.java
                .isAssignableFrom(authentication)
    }

    companion object {
        internal val ipAuthorityMap: MutableMap<String, SimpleGrantedAuthority> = ConcurrentHashMap()

        init {
            ipAuthorityMap["127.0.0.1"] = SimpleGrantedAuthority("ADMIN")
//            ipAuthorityMap["10.236.69.103"] = SimpleGrantedAuthority("ADMIN")
//            ipAuthorityMap["10.236.69.104"] = SimpleGrantedAuthority("FRIEND")
        }
    }
}

fun auth(){

}