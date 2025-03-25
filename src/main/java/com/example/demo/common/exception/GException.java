package com.example.demo.common.exception;

import org.springframework.http.HttpStatus;

public class GException extends RuntimeException {

    private GErrorInterface error;

    public GException(GErrorInterface error) {
        this(error, error.getMessage());
    }

    public GException(GErrorInterface error, String message) {
        super(message);
        this.error = error;
    }

    public GException(String message) {
        super(message);
    }

    public String getCode() {
        return error.getCode();
    }

    public HttpStatus getHttpStatus() {
        return error.getStatus();
    }
}
