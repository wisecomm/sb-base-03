package com.example.demo.common.exception;

import org.springframework.http.HttpStatus;

public interface GErrorInterface {
    public HttpStatus getStatus();
    public String getCode();
    public String getMessage();
}
