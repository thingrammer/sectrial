//package com.example.demo.config.security
//
//import com.example.demo.CustomDetailsService
//import org.springframework.beans.factory.annotation.Autowired
//import org.springframework.context.annotation.Bean
//import org.springframework.context.annotation.Configuration
//import org.springframework.security.authentication.AuthenticationManager
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
//import org.springframework.security.config.annotation.web.builders.HttpSecurity
//import org.springframework.security.config.annotation.web.builders.WebSecurity
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
//import org.springframework.security.config.http.SessionCreationPolicy
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
//import org.springframework.security.crypto.password.PasswordEncoder
//import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
//import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
//import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
//import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
//import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
//import org.springframework.beans.factory.annotation.Qualifier
//import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
//
//
//
//
//@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//class SecurityConfiguration : WebSecurityConfigurerAdapter() {
//    @Autowired
//    private val customDetailsService: CustomDetailsService? = null
//
//    @Bean
//    fun encoder(): PasswordEncoder {
//        return BCryptPasswordEncoder()
//    }
//
//    @Autowired
//    override fun configure(auth: AuthenticationManagerBuilder?) {
//        auth!!.userDetailsService<CustomDetailsService>(customDetailsService).passwordEncoder(encoder())
//    }
//
//    override fun configure(http: HttpSecurity) {
//        http.authorizeRequests().anyRequest().authenticated().and().sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
//    }
//
//    override fun configure(web: WebSecurity?) {
//        web!!.ignoring()
//    }
//
//    @Bean
//    override fun authenticationManagerBean(): AuthenticationManager {
//        return super.authenticationManagerBean()
//    }
//}
//
//
//@Configuration
//class OAuth2Config : AuthorizationServerConfigurerAdapter() {
//    private val clientid = "fat_client"
//    private val clientSecret = "secret_key"
//    private val privateKey = """MGMCAQACEQC20r7anj/dmyl9m2yWKSpdAgMBAAECEDIbbKeqe8KWj5x67mjKAZkCCQDbsyCxWMs3FwIJANUH0EojKlKrAgg/vZqwmXhsBQIJANIXj6LeBWpbAgkAoyKHOJ3qSpc="""
//    private val publicKey = """MCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRALbSvtqeP92bKX2bbJYpKl0CAwEAAQ=="""
//
//    @Autowired
//    @Qualifier("authenticationManagerBean")
//    private val authenticationManager: AuthenticationManager? = null
//
//    @Bean
//    fun tokenEnhancer(): JwtAccessTokenConverter {
//        val converter = JwtAccessTokenConverter()
////        converter.setSigningKey(privateKey)
////        converter.setVerifierKey(publicKey)
//        return converter
//    }
//
//    @Bean
//    fun tokenStore(): JwtTokenStore {
//        return JwtTokenStore(tokenEnhancer())
//    }
//
//    @Throws(Exception::class)
//    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer?) {
//        endpoints!!.authenticationManager(authenticationManager).tokenStore(tokenStore())
//                .accessTokenConverter(tokenEnhancer())
//    }
//
//    @Throws(Exception::class)
//    override fun configure(security: AuthorizationServerSecurityConfigurer?) {
//        security!!.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()")
//    }
//
//    @Throws(Exception::class)
//    override fun configure(clients: ClientDetailsServiceConfigurer?) {
//        clients!!.inMemory().withClient(clientid).secret(clientSecret).scopes("read", "write")
//                .authorizedGrantTypes("password", "refresh_token").accessTokenValiditySeconds(20000)
//                .refreshTokenValiditySeconds(20000)
//
//    }
//}