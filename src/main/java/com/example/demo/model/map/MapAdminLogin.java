package com.example.demo.model.map;

import java.util.Date;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class MapAdminLogin {
    private String accessToken;
    private String refreshToken;
    private String corpCode;
    private String manCorpCode;
    private Date loginTimeCurrent;
    private Date loginTimeLast;
    private String loginIp;
    // 권한ID
    private String roleid;
}
