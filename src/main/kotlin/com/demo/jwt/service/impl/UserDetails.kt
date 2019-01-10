package com.demo.jwt.service.impl

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service


@Service
class UserDetailsServiceAdapter : UserDetailsService {
    companion object {
        val userData = mutableMapOf(
                "fat" to "ps"
        )
    }

    override fun loadUserByUsername(username: String): UserDetails {
        val password = userData[username]
                ?: throw UsernameNotFoundException(username)
        return User(
                username,
                BCryptPasswordEncoder().encode(password),
                emptyList()
//                mutableListOf(SimpleGrantedAuthority("JWT_AUTH"))
        )
    }

    open fun saveUser(username: String, password: String) {
        userData[username] = BCryptPasswordEncoder().encode(password)
    }

}