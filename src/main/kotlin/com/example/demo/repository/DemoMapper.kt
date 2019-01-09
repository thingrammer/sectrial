package com.example.demo.repository

import org.apache.ibatis.annotations.Mapper
import org.apache.ibatis.annotations.Select

@Mapper
interface DemoMapper {
    @Select("select *  from tt ")
    fun get(): List<Map<String, Any>>
}