package com.example.demo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.example.demo.common.model.GResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.SecretKey;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Service
public class GJwtTokenHelper {
    public static final String JWT_USER_ID = "USER_ID";
    public static final String JWT_USER_ROLE = "USER_ROLE";
    public static final String JWT_CORP_CODE = "CORP_CODE";

    private SecretKey JWT_SECRET_KEY;
    private int jwtAccessTokenExp;
    private int jwtRefreshTokenExp;

    /**
     * JWT_SECRET_KEY 변수값에 환경 변수에서 불러온 SECRET_KEY를 주입합니다.
     */
    public GJwtTokenHelper(@Value("${jwt.secret-key}") String jwtSecretKey,
        @Value("${jwt.access-token-expiration-min}") int jwtAccessTokenExp,
        @Value("${jwt.refresh-token-expiration-day}") int jwtRefreshTokenExp ) {
        this.JWT_SECRET_KEY = Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
        this.jwtAccessTokenExp = jwtAccessTokenExp * 60 * 1000; // 분
        this.jwtRefreshTokenExp = jwtRefreshTokenExp * 24 * 60 * 60 * 1000;  // 일자
    }


    public String generateJwt(String userId, String role, String corpCode) {
        JwtBuilder builder = Jwts.builder()
            .claim(GJwtTokenHelper.JWT_USER_ID, userId)
            .claim(GJwtTokenHelper.JWT_USER_ROLE, role)
            .claim(GJwtTokenHelper.JWT_CORP_CODE, corpCode)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + jwtAccessTokenExp))
            .signWith(JWT_SECRET_KEY);
        return builder.compact();
    }

    public String generateRefreshToken(String userId, String role, String corpCode) {
        JwtBuilder builder = Jwts.builder()
        .claim(GJwtTokenHelper.JWT_USER_ID, userId)
        .claim(GJwtTokenHelper.JWT_USER_ROLE, role)
        .claim(GJwtTokenHelper.JWT_CORP_CODE, corpCode)
        .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + jwtRefreshTokenExp))
            .signWith(JWT_SECRET_KEY);
        return builder.compact();
    }

    /**
     * 'Header' 내에서 'Token' 정보를 반환하는 메서드
     *
     * @param header 헤더
     * @return String
     */
    public String getHeaderToToken(String header) {
        return header.split(" ")[1];
    }


    /**
     * 'JWT' 내에서 'Claims' 정보를 반환하는 메서드
     *
     * @param token : 토큰
     * @return Claims : Claims
     */

    private Claims getTokenToClaims(String token) {
        return Jwts.parser()
                .verifyWith(JWT_SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getCurrentAuthTokenRequest() {
        // Try to get current request using RequestContextHolder
        try {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String authHeader = request.getHeader("Authorization");
            return getHeaderToToken(authHeader);
        } catch (IllegalStateException e) {
            log.warn("Not called within request context - RequestContextHolder not available");
        }
        
        // Fall back to SecurityContext if request isn't available
        return "";
    }

    public String getClaimsToUserId() {
        String token = getCurrentAuthTokenRequest();
        if(token == null || token.isEmpty()) {
            return "";
        }
        Claims claims = getTokenToClaims(token);
        return claims.get(GJwtTokenHelper.JWT_USER_ID).toString();
    }


    public String getClaimsToUserRole() {
        String token = getCurrentAuthTokenRequest();
        if(token == null || token.isEmpty()) {
            return "";
        }
        Claims claims = getTokenToClaims(token);
        return claims.get(GJwtTokenHelper.JWT_USER_ROLE).toString();
    }
    public String getClaimsToUserCorpCode() {
        String token = getCurrentAuthTokenRequest();
        if(token == null || token.isEmpty()) {
            return "";
        }
        Claims claims = getTokenToClaims(token);
        return claims.get(GJwtTokenHelper.JWT_CORP_CODE).toString();
    }

    /**
     * 토큰을 기반으로 유효한 토큰인지 여부를 반환해주는 메서드
     * - Claim 내에서 사용자 정보를 추출합니다.
     *
     * @param token String  : 토큰
     * @return boolean      : 유효한지 여부 반환
     */
    public ValidToken isValidToken(String token) {
        try {
            Claims claims = getTokenToClaims(token);
            log.info("expireTime :{}", claims.getExpiration());
            log.info("userId :" + claims.get("userId"));
            log.info("role :" + claims.get("role"));
            return ValidToken.builder().isValid(true).errorName(null).build();
        } catch (ExpiredJwtException exception) {
            log.error("Token Expired", exception);
            return ValidToken.builder().isValid(false).errorName("TOKEN_EXPIRED").build();
        } catch (JwtException exception) {
            log.error("Token Tampered", exception);
            return ValidToken.builder().isValid(false).errorName("TOKEN_INVALID").build();
        } catch (NullPointerException exception) {
            log.error("Token is null", exception);
            return ValidToken.builder().isValid(false).errorName("TOKEN_NULL").build();
        }
    }

    public void sendHttpResponseTokenError(HttpServletResponse response, Exception e) {
        try {
            GResponse gResponse = new GResponse("E403", "토큰 에러.");

            String resultMsg = "";

            // [CASE1] JWT 기간 만료
            if (e instanceof ExpiredJwtException) {
                resultMsg = "토큰 기간이 만료되었습니다.";
            }
            // [CASE2] JWT내에서 오류 발생 시
            else if (e instanceof JwtException) {
                resultMsg = "잘못된 토큰이 발급되었습니다.";
            }
            // [CASE3] 이외 JWT내에서 오류 발생
            else {
                resultMsg = "OTHER TOKEN ERROR : " + e.getMessage();
            }
    
            gResponse.setMessage(resultMsg);
            gResponse.setStatus(403);
    
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();

            ObjectMapper objectMapper = new ObjectMapper();
            printWriter.print(objectMapper.writeValueAsString(gResponse));
            printWriter.flush();
            printWriter.close();
        } catch (Exception exception) {
            log.error("sendHttpResponseTokenError Exception:", exception);
        }
    }

    public void sendHttpResponseTokenRefresh(HttpServletResponse response, String refreshToken) {
        try {
            String resultMsg = "토큰이 유효하지 않습니다.";

            GResponse gResponse = new GResponse("E401", resultMsg);

            Claims claims = getTokenToClaims(refreshToken);
            String userId = claims.get(GJwtTokenHelper.JWT_USER_ID).toString();
            String role = claims.get(GJwtTokenHelper.JWT_USER_ROLE).toString();
    
            String jwt = generateJwt(userId, role, "1234");
            gResponse.setData(jwt);
            gResponse.setStatus(401);
    
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();

            ObjectMapper objectMapper = new ObjectMapper();
            printWriter.print(objectMapper.writeValueAsString(gResponse));
                printWriter.flush();
            printWriter.close();
        } catch (Exception exception) {
            log.error("sendHttpResponseTokenRefresh Exception:", exception);
        }
    }

}

