package com.example.demo

import com.example.demo.provider.Data
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.mybatis.spring.boot.test.autoconfigure.MybatisTest
import org.springframework.test.context.junit4.SpringRunner
import org.junit.runner.RunWith
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase

//@SpringBootApplication
//class TestApplication

@RunWith(SpringRunner::class)
@MybatisTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class CityMapperTest {

    @Autowired
    lateinit var map: Data

    @Test
    fun findByStateTest() {
        System.err.println(map.get())

    }

}