package com.example.demo.common.model;

import java.util.Date;
import org.springframework.http.HttpStatus;
import lombok.Data;

@Data
public class GResponse {

    Date date;
    Integer status;
    String error;

    String code;
    String message;
    Object data;

    public GResponse(String code, String message) {
        this(code, message, null);
    }

    public GResponse(String code, Object data) {
        this(code, null, data);
    }

    public GResponse(String code, String message, Object data) {
        this.date = null;
        this.status = null;
        this.error = null;
        
        this.code = code;
        this.message = message;
        this.data = data;
    }

    /**
     * for error
     */
   public GResponse(HttpStatus httpStatus, String code, String message) {
        this.date = new Date();
        this.status = httpStatus.value();
        this.error = httpStatus.name();
        this.code = code;
        this.message = message;
        
        this.data = null;
    }
}
