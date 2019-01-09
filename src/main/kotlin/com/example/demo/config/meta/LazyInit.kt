package com.example.demo.config.meta

import org.springframework.beans.BeansException
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.beans.factory.config.BeanFactoryPostProcessor
import org.springframework.context.annotation.Configuration


//@Configuration
//class LazyInitBeanFactoryPostProcessor : BeanFactoryPostProcessor {
//    @Throws(BeansException::class)
//    override fun postProcessBeanFactory(beanFactory: ConfigurableListableBeanFactory) {
//        for (beanName in beanFactory.beanDefinitionNames) {
//            beanFactory.getBeanDefinition(beanName).isLazyInit = true
//        }
//    }
//}