package com.example.demo

import com.example.demo.provider.OAuthDao
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service


@Service
class CustomDetailsService : UserDetailsService {
    @Autowired
    internal var oauthDao: OAuthDao? = null

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): CustomUser {
        var userEntity: UserEntity? = null
        try {
            userEntity = oauthDao!!.getUserDetails(username)
            return CustomUser(userEntity)
        } catch (e: Exception) {
            e.printStackTrace()
            throw UsernameNotFoundException("User $username was not found in the database")
        }

    }
}