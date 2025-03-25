package com.example.demo.common;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

import com.example.demo.common.exception.GError;
import com.example.demo.common.exception.GErrorInterface;

@AllArgsConstructor
@Getter
public enum BsError implements GErrorInterface {

    UNAUTHORIZED(GError.UNAUTHORIZED)
    , FORBIDDEN(GError.FORBIDDEN)
    , INVALID_PARAM(GError.FORBIDDEN)

    , DUPLICATED_LOGIN(HttpStatus.OK, "BS1000", "중복 로그인입니다.")
    , EXPIRED_LOGIN(HttpStatus.OK, "BS1001", "로그인 시간이 만료되었습니다.")
    ;

    private final HttpStatus status;
    private final String code;
    private final String message;

    private BsError(GError error) {
        this(error.getStatus(), error.getCode(), error.getMessage());
    }
}
