package com.anuj.auth.utils;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthPrincipal {
    private String sub;
    private String tenantName;
    private String groups;
    private boolean emailVerified;
    private String issuer;
    private String username;
    private String originJti;
    private String audience;
    private String eventId;
    private String tokenUse;
    private long authTime;
    private long exp;
    private long iat;
    private String jti;
    private String email;

}