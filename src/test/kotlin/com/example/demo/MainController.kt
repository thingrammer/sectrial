package com.example.demo

import com.example.demo.controller.BaseController
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
    lateinit var baseController: BaseController

    @Test
    fun testMainController() {
//        val take = baseController.take()
//        val get = baseController.get()
//        println(take)
//        println(get)
    }
}
//class DataImpl : DataService() {
//    override fun getDemoMapper(): Any {
//        return "fucks"
//    }
//}