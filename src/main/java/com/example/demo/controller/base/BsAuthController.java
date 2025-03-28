package com.example.demo.controller.base;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.common.exception.GException;
import com.example.demo.common.model.GResponse;
import com.example.demo.model.map.MapAdminLogin;
import com.example.demo.service.base.LoginService;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/api/v1/base/auth")
@RestController
@RequiredArgsConstructor
public class BsAuthController {

    //..
    private final LoginService loginService;

	@Operation(summary = "관리자 로그인")
    @PostMapping("/adminlogin")
	public ResponseEntity<GResponse> adminlogin(HttpServletRequest request
                                            	, HttpServletResponse response
												, @RequestParam String userId, @RequestParam String userPw) throws GException {
		log.info("adminlogin 메소드 콜");
		
		MapAdminLogin mapAdminLogin = loginService.adminLogin(null, userId, userPw);

        return ResponseEntity.ok().body(new GResponse("0000", "0000 리턴 메시지", mapAdminLogin));
	}

    @Operation(summary = "로그인 정보 테스트( token 으로 로그인 정보 가져오기 )")
    @PostMapping("/logininfo")
	public ResponseEntity<GResponse> logininfo() throws GException {
		String strTemp = loginService.getTest();

		return ResponseEntity.ok().body(new GResponse("0000", "", strTemp));
	}
	
}
