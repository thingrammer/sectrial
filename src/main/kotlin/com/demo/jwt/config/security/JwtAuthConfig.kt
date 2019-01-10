package com.demo.jwt.config.security

import com.demo.jwt.service.impl.UserDetailsServiceAdapter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureOrder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource


@AutoConfigureOrder
@Configuration
class WebSecurity(private var userDetailsService: UserDetailsServiceAdapter,
                  private var bCryptPasswordEncoder: BCryptPasswordEncoder) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
                .cors().and().csrf().disable().authorizeRequests()
//                .antMatchers(HttpMethod.POST, JwtProperties.SIGN_UP_URL).permitAll()
//                .antMatchers(*UriHandler.uris.toTypedArray()).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterAfter(JWTAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter::class.java)
                .addFilterAfter(JWTAuthorizationFilter(authenticationManager()), JWTAuthenticationFilter::class.java)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    }

    @Autowired
    fun configureGlobal(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService<UserDetailsService>(userDetailsService).passwordEncoder(bCryptPasswordEncoder)
    }

    override fun configure(web: org.springframework.security.config.annotation.web.builders.WebSecurity?) {
        web!!.ignoring()
                .antMatchers(*UriHandler.uris.toTypedArray())
                .antMatchers(HttpMethod.POST, JwtProperties.SIGN_UP_URL)

    }

    @Bean
    internal fun corsConfigurationSource(): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", CorsConfiguration().applyPermitDefaultValues())
        return source
    }
}

