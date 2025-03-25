package com.example.demo.controller;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.common.exception.GError;
import com.example.demo.common.exception.GException;
import com.example.demo.common.model.GResponse;
import com.example.demo.model.map.UserMap;
import com.example.demo.service.LoginService;
import com.example.demo.service.UserService;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
public class GreetingController {

    //..
    private final LoginService loginService;

	private final UserService userService;
		
    @Operation(summary = "기본 테스트")
	@GetMapping("/greeting")
	public ResponseEntity<GResponse> greeting(@RequestParam(value = "name", defaultValue = "World") String name) {
		log.info("greeting 메소드 콜");

		return ResponseEntity.ok().body(new GResponse("0000", "greeting 리턴 메시지", name));
	}

	@Operation(summary = "관리자 로그인")
    @PostMapping("/adminlogin")
	public ResponseEntity<GResponse> adminlogin(HttpServletRequest request
                                            	, HttpServletResponse response
												, @RequestParam String userId, @RequestParam String userPw) {
		log.info("adminlogin 메소드 콜");

		/*
		UserDetailsDto userDetailsDto = (UserDetailsDto) userDetailsService.loadUserByUsername(userId);
		if (!(userDetailsDto.getUserPw().equalsIgnoreCase(userPw))) {
			throw new BadCredentialsException(userDetailsDto.getUserNm() + "Invalid password");
		}

//		userService.selectUserList(null);


        return ResponseEntity.ok().body(new GResponse("0000", "0000 리턴 메시지", userDetailsDto));
		*/
		userService.getUserById(userId);
		
		String jwt = loginService.login(null, userId, userPw);

        return ResponseEntity.ok().body(new GResponse("0000", "0000 리턴 메시지", jwt));
	}
    
}
