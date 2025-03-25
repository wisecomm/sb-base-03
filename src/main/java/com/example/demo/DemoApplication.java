package com.example.demo;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin
// DataSourceAutoConfiguration.class : 초기 실행 시 url 에러시 디비 사용하지 않음
// SecurityAutoConfiguration.class : 시큐리티 사용하지 않음 ( auth 페이지 나옴)
@SpringBootApplication(exclude={SecurityAutoConfiguration.class})
@MapperScan(basePackages = "com.example.demo.mapper")
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
