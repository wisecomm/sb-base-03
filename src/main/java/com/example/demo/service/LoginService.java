package com.example.demo.service;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.example.demo.common.model.GResponse;
import com.example.demo.jwt.GJwtTokenHelper;
import com.example.demo.model.map.MapAdminLogin;
import com.example.demo.model.map.UserMap;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService {

    //..
    private final GJwtTokenHelper jwtTokenHelper;
    private final UserService userService;

    //..
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public MapAdminLogin adminLogin(HttpServletRequest request, String userId, String userPwd) {
		Optional<UserMap> userOptional = userService.getUserById(userId);

        MapAdminLogin mapAdminLogin = new MapAdminLogin();

        String jwt = jwtTokenHelper.generateJwt(userOptional.get().getUserId(), "ADMIN", "1234");
        mapAdminLogin.setAccessToken(jwt);
        jwt = jwtTokenHelper.generateRefreshToken(userOptional.get().getUserId(), "ADMIN", "1234");
        mapAdminLogin.setRefreshToken(jwt);

        return mapAdminLogin;
    }

    public String getTest() {
        return jwtTokenHelper.getClaimsToUserId();
    }

}