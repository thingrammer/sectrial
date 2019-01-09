package com.example.demo

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import java.time.LocalDateTime

data class Res(
        var id: Int,
        var date: LocalDateTime,
        var type: String)

data class UserEntity(var name: String,
                      var password: String,
                      var authorities: Set<GrantedAuthority>)

class CustomUser(user: UserEntity) : User(user.name, user.password, user.authorities) {
    companion object {
        private val serialVersionUID = 1L
    }
}