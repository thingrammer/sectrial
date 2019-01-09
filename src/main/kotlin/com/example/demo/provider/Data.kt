package com.example.demo.provider

import com.example.demo.Res
import org.apache.ibatis.annotations.Mapper
import org.apache.ibatis.annotations.Select

@Mapper
interface Data {
    @Select("select *  from tt ")
    fun get(): List<Map<String, Res>>
}