package com.example.demo.common.exception;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.example.demo.common.model.GResponse;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class RcExceptionHandler {

    // 
    @ExceptionHandler({ Exception.class })
    public ResponseEntity<GResponse> gwExceptionHandler(Exception ex, HttpServletRequest request) {
        log.error("Exception : {}", ex);
        GError error = GError.INVALID_PARAM;
        // String message = ex.getClass().toString();
        // String message = ex.getMessage();
        String message = "요청 처리중 오류가 발생하였습니다.\n관리자에게 문의하세요.";
        return new ResponseEntity<>(new GResponse(error.getStatus(), error.getCode(), message), error.getStatus());
    }

    /**
     * GWServer 자체 에러 처리
     * @param ex
     * @param request
     * @return
     */
    @ExceptionHandler({GException.class})
    public ResponseEntity<GResponse> gwExceptionHandler(GException ex, HttpServletRequest request) {
        log.error("GException : {}", ex);
        return new ResponseEntity<>(new GResponse(ex.getHttpStatus(), ex.getCode(), ex.getMessage()), ex.getHttpStatus());
    }

    /**
     * Request Parameters @Valid 에 대한 오류 처리
     * @param ex
     * @param request
     * @return
     */
    @ExceptionHandler({org.springframework.validation.BindException.class})
    public ResponseEntity<GResponse> bindExceptionHandler(org.springframework.validation.BindException ex, HttpServletRequest request) {
        log.error("BindException : {}", ex);
        GError error = GError.INVALID_PARAM;
        String message = String.format("invalid parameter : [%s]", ex.getFieldError().getField());
        log.debug("message : {}", message);
        return new ResponseEntity<>(new GResponse(error.getStatus(), error.getCode(), message), error.getStatus());
    }

    /**
     * Authentication 미인증 오류 처리
     * @param ex
     * @param request
     * @return
     */
    @ExceptionHandler({org.springframework.security.core.AuthenticationException.class})
    public ResponseEntity<GResponse> handleAuthenticationException(org.springframework.security.core.AuthenticationException ex, HttpServletRequest request) {
        log.error("AuthenticationException : {}", ex);
        GError error = GError.UNAUTHORIZED;
        return new ResponseEntity<>(new GResponse(error.getStatus(), error.getCode(), error.getMessage()), error.getStatus());
    }

    /**
     * Forbidden 권한없음 오류 처리
     * @param ex
     * @param request
     * @return
     */
    @ExceptionHandler({org.springframework.security.access.AccessDeniedException.class})
    public ResponseEntity<GResponse> handleAuthenticationException(org.springframework.security.access.AccessDeniedException ex, HttpServletRequest request) {
        log.error("AccessDeniedException : {}", ex);
        GError error = GError.FORBIDDEN;
        return new ResponseEntity<>(new GResponse(error.getStatus(), error.getCode(), error.getMessage()), error.getStatus());
    }

    // TODO: dhlee: 필요에 따라 아래 exception 도 발생하는지 확인필요
    // MissingServletRequestParameterException.class: request parameter가 없을 때 에러를 리턴한다.
    // MissingRequestHeaderException.class: request header가 없을 때 에러를 리턴한다.
    // MethodArgumentNotValidException.class: request body의 데이터가 유효하지 않을 때 에러를 리턴한다.
    // NoHandlerFoundException.class: 404 error를 리턴한다.
}
