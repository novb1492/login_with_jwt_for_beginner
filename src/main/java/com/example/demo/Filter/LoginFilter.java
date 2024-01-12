package com.example.demo.Filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import org.json.simple.JSONObject;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Slf4j
public class LoginFilter  extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private  String jwtSecret="jwtSecret";
    private  long jwtExpirationInMs=1;
    private  long refreshExpirationInMs=30;
    public LoginFilter(AuthenticationManager authenticationManager){
        this.authenticationManager=authenticationManager;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)throws AuthenticationException {
        log.info("로그인 필터 입장");
        ObjectMapper objectMapper=new ObjectMapper();
        JSONObject jsonObject=new JSONObject();
        try {
            jsonObject = objectMapper.readValue(request.getInputStream(), JSONObject.class);
            log.info("로그인시도 정보:{}",jsonObject);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jsonObject.get("id"),jsonObject.get("pwd")));
        } catch (IOException e) {
            log.error("요청에서 JSON 데이터를 읽는 중 오류 발생", e);
            throw new AuthenticationServiceException("요청에서 JSON 데이터를 읽는 중 오류 발생", e);
        }

    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("로그인 성공");

        // 로그인 성공 시 JWT 토큰 발급
        String jwtToken = generateToken("access", jwtExpirationInMs);
        String refreshToken = generateToken("refresh", refreshExpirationInMs);

        // JWT 토큰을 응답 쿠키에 추가
        ResponseCookie jwtCookie = ResponseCookie.from("access_token", jwtToken)
                .path("/")
                .httpOnly(true)
                .maxAge(jwtExpirationInMs / 1000)
                .sameSite("None")
                .secure(true)
                .build();
        response.addHeader("Set-Cookie", jwtCookie.toString());

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                .path("/")
                .httpOnly(true)
                .maxAge(refreshExpirationInMs / 1000)
                .sameSite("None")
                .secure(true)
                .build();
        response.addHeader("Set-Cookie", refreshCookie.toString());

        // 로그인 성공 시 200 응답 코드만 반환
        response.setStatus(HttpServletResponse.SC_OK);

        // 응답 본문에 JSON 추가
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(Map.of("message", "login done"));
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.info("로그인실패:{}",failed.getMessage());
        // 로그인 실패 응답 설정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 예시로 401 Unauthorized 상태 코드를 설정

        // 실패 메시지를 JSON 형식으로 응답에 추가
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "Authentication failed");
        errorResponse.put("message", failed.getMessage());

        response.setContentType("application/json");
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));

        response.getWriter().flush();


    }
    private String generateToken(String username, long expiration) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(jwtSecret);
            Date expiryDate = new Date(System.currentTimeMillis() + expiration);

            return JWT.create()
                    .withSubject(username)
                    .withIssuedAt(new Date())
                    .withExpiresAt(expiryDate)
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            throw new RuntimeException("Error creating JWT token", e);
        }
    }
}