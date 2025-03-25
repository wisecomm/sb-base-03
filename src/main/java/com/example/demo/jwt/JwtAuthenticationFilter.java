package com.example.demo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.micrometer.common.util.StringUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String HTTP_METHOD_OPTIONS = "OPTIONS";
    private static final String ACCESS_TOKEN_HEADER_KEY = "Authorization";
    private static final String REFRESH_TOKEN_HEADER_KEY = "x-refresh-token";
    private static final List<String> WHITELIST_URLS = Arrays.asList(
            "/api/v1/user/login",
            "/api/v1/token/token",
            "/user/login",
            "/token/token",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/greeting",
            "/adminlogin"
    );

    private final GJwtTokenHelper jwtTokenHelper;

    public JwtAuthenticationFilter(GJwtTokenHelper jwtTokenHelper) {
        this.jwtTokenHelper = jwtTokenHelper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException, IOException {

        String requestURI = request.getRequestURI();
        // [STEP1] 토큰이 필요하지 않는 API 호출 발생 혹은 토큰이 필요없는 HTTP Method OPTIONS 호출 시 : 아래 로직 처리 없이 다음 필터로 이동
        if (isWhitelistedPath(requestURI) || HTTP_METHOD_OPTIONS.equalsIgnoreCase(request.getMethod())) {
            logger.warn("1111===JWT Token is missing");
            chain.doFilter(request, response);
            return;     // 종료
        }

        logger.warn("2222===JWT Token is missing");

        try {
            // [STEP2] Header 내에 Authorization, x-refresh-token를 확인하여 접근/갱신 토큰의 존재여부를 체크합니다.
            String accessTokenHeader = request.getHeader(ACCESS_TOKEN_HEADER_KEY);
            String refreshTokenHeader = request.getHeader(REFRESH_TOKEN_HEADER_KEY);


            // [STEP2-1] 토큰이 존재하면 다음 프로세스를 진행합니다.
            if (StringUtils.isNotBlank(accessTokenHeader) || StringUtils.isNotBlank(refreshTokenHeader)) {

                String paramAccessToken = jwtTokenHelper.getHeaderToToken(accessTokenHeader);
                String paramRefreshToken = jwtTokenHelper.getHeaderToToken(refreshTokenHeader);

                // [STEP4] 접근 토큰(Access Token)의 유효성을 체크합니다.
                ValidToken accTokenValid = jwtTokenHelper.isValidToken(paramAccessToken);

                // [STEP5-1] 접근 토큰이 유효하다면 다음 프로세스를 진행합니다.
                if (accTokenValid.isValid()) {
                    // [STEP6] 접근 토큰(Access Token)내에 전달하려는 사용자 정보를 확인합니다.
                    // [STEP6-1] 사용자 정보가 존재한다면 다음 필터로 이동을 합니다.
                    if (StringUtils.isNotBlank(jwtTokenHelper.getClaimsToUserId(paramAccessToken))) {
                        chain.doFilter(request, response);
                    }
                    // [STEP6-2] 사용자 정보가 존재하지 않는 다면 에러 메시지를 클라이언트에게 전달합니다.
                    else {
                        throw new Exception("토큰 내에 사용자 아이디가 존재하지 않습니다");
                    }
                }
                // [STEP5-2] 접근 토큰이 존재하지 않으면 접근 토큰의 에러 정보를 확인합니다.
                else {
                    // [STEP6] 접근 토큰(Access Token)에서 발생한 오류가 만료된 (TOKEN_EXPIRED)오류 인지를 체크합니다.
                    // [STEP6-1] 오류가 토큰이 만료된 오류 인 경우 다음 프로세스를 진행합니다.
                    if (accTokenValid.getErrorName().equals("TOKEN_EXPIRED")) {

                        // [STEP7] 리프레시 토큰(Refresh Token)이 유효한지 체크를 합니다.
                        // [STEP7-1] 리프레시 토큰이 유효하다면 접근 토큰을 갱신합니다. 갱신하여 재 생성된 접근 토큰을 반환합니다.
                        if (jwtTokenHelper.isValidToken(paramRefreshToken).isValid()) {
                            
                            // danyoh : 수정 필요

                            // Token 내에 사용자 정보를 추출하고 이를 기반으로 토큰을 생성합니다.
//                            UserDto claimsToUserDto = TokenUtils.getClaimsToUserDto(paramRefreshToken, false);
//                            System.out.println("claimsToUserDto ::  " + claimsToUserDto);


//                            String token = TokenUtils.generateJwt(claimsToUserDto);         // 접근 토큰(AccessToken)을 새로 발급합니다.
//                            sendToClientAccessToken(token, response);                       // 발급한 접근 토큰을 클라이언트에게 전달합니다.
                            chain.doFilter(request, response);                              // 리소스로 접근을 허용합니다.
                        }
                        // [STEP7-2] 리프레시 토큰이 유효하지 않다면 에러 메시지를 클라이언트에게 전달합니다.
                        else {
                            throw new Exception("재 로그인이 필요합니다.");
                        }
                    }
                    // [STEP7-2] 오류가 토큰이 만료된 경우가 아닌 경우 에러 메시지를 클라이언트에게 전달합니다.
                    throw new Exception("토큰이 유효하지 않습니다.");                      // 토큰이 유효하지 않은 경우
                }
            }
            // [STEP2-2] 토큰이 존재하지 않으면 “토큰이 존재하지 않습니다”라는 에러메시지를 클라이언트에게 전달합니다.
            else {
                throw new Exception("토큰이 존재하지 않습니다.");                          // 토큰이 존재하지 않는 경우
            }
        }
        // Token 내에 Exception 발생 하였을 경우 : 클라이언트에 응답값을 반환하고 종료합니다.
        catch (Exception e) {
            jwtTokenHelper.sendHttpResponseTokenError(response, e);
        }
    }

    /**
     * 화이트리스트에 등록된 경로인지 확인합니다.
     * 
     * @param requestURI 요청 URI
     * @return 화이트리스트 경로이면 true, 아니면 false
     */
    private boolean isWhitelistedPath(String requestURI) {
        // 정확한 경로 매칭
        if (WHITELIST_URLS.contains(requestURI)) {
            return true;
        }
        
        // 와일드카드 경로 매칭
        for (String whitelistedUrl : WHITELIST_URLS) {
            if (whitelistedUrl.endsWith("/**")) {
                String prefix = whitelistedUrl.substring(0, whitelistedUrl.length() - 2);
                if(prefix.endsWith("/")) {
                    prefix = prefix.substring(0, prefix.length() - 1);
                }
                if (requestURI.startsWith(prefix)) {
                    return true;
                }
            }
        }
        
        return false;
    }    


}
