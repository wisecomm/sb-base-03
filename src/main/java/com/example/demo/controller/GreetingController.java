package com.example.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.common.exception.GException;
import com.example.demo.common.model.GResponse;
import com.example.demo.model.param.ParamTest01;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/api/v1/greeting")
@RestController
@RequiredArgsConstructor
public class GreetingController {

    @Operation(summary = "화이트 리스트 테스트( 로그인 없이 접근 가능 )")
	@GetMapping("/greeting")
	public ResponseEntity<GResponse> greeting(@RequestParam(value = "name", defaultValue = "World") String name) throws GException {
		log.info("greeting 메소드 콜");

		return ResponseEntity.ok().body(new GResponse("0000", "greeting 리턴 메시지", name));
	}

    @Operation(summary = "파라메터 전달 샘플")
    @PostMapping("/param01")
	public ResponseEntity<GResponse> param01(@RequestBody ParamTest01 paramTest01) throws GException {
		log.info("param01 메소드 콜=" + paramTest01.toString());
		return ResponseEntity.ok().body(new GResponse("0000", "", "param01"));
	}


}
