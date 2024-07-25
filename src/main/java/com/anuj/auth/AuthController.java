package com.anuj.auth;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SecurityRequirement(name = "token")
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @GetMapping("/data")
    public ResponseEntity<Object> getData() {
        Object data = authService.getData();
        if (data != null) {
            return ResponseEntity.ok().body(data);
        }
        return ResponseEntity.badRequest().body("Token error");
    }

}
