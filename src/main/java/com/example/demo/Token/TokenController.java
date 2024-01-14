package com.example.demo.Token;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @PostMapping("/pass/refresh")
    public ResponseEntity<?>reToken(HttpServletRequest request, HttpServletResponse response){
        return tokenService.refreshAccessToken(request,response);
    }
}
