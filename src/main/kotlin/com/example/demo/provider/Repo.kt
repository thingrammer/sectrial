package com.example.demo.provider

import com.example.demo.UserEntity
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Repository


@Repository
class OAuthDao {

    fun getUserDetails(username: String): UserEntity {
//        val grantedAuthoritiesList = ArrayList<GrantedAuthority>()
//        val userSQLQuery = "SELECT * FROM USERS WHERE USERNAME=?"
//        val list = jdbcTemplate!!.query(userSQLQuery, arrayOf(username)
//        ) { rs: ResultSet, rowNum: Int ->
//
//            val user = UserEntity()
//            user.setUsername(username)
//            user.password = rs.getString("PASSWORD")
//            user
//        }
//        if (list.size > 0) {
//            val grantedAuthority = SimpleGrantedAuthority("ROLE_SYSTEMADMIN")
//            grantedAuthoritiesList.add(grantedAuthority)
//            list[0].setGrantedAuthoritiesList(grantedAuthoritiesList)
//            return list[0]
//        }
        return UserEntity("fat",
                "ps",
                setOf(SimpleGrantedAuthority("ROLE_ADMIN")))
    }
}