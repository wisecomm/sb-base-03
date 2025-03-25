package com.example.demo.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import org.springframework.http.HttpStatus;

@Getter
@ToString
@AllArgsConstructor
public enum GError implements GErrorInterface {

    /**
     * 인증안됨
     */
    UNAUTHORIZED(HttpStatus.OK, "E0001", "UNAUTHORIZED"),
    /**
     * 권한없음
     */
    FORBIDDEN(HttpStatus.OK, "E0002", "ACCESS_DENIED"),


    
    /**
     * 잘못된 파라미터
     */
    INVALID_PARAM(HttpStatus.OK, "E1001", "INVALID_PARAMETER"),
    ;   




    private final HttpStatus status;
    private final String code;
    private final String message;


    // GError(HttpStatus status, String code, String message) {
    //     this.status = status;
    //     this.code = code;
    //     this.message = message;
    // }
}