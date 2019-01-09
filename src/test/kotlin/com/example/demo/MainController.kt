package com.example.demo

import com.example.demo.controller.HtmlController
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mybatis.spring.boot.test.autoconfigure.MybatisTest
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase

@RunWith(MockitoJUnitRunner::class)
@MybatisTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class MainControllerTest {
//    @Autowired
    @Mock
//    var dataService: DataService = DataImpl()

    @InjectMocks
    lateinit var htmlController: HtmlController

    @Test
    fun testMainController() {
//        val take = htmlController.take()
//        val get = htmlController.get()
//        println(take)
//        println(get)
    }
}
//class DataImpl : DataService() {
//    override fun getData(): Any {
//        return "fucks"
//    }
//}