package com.example.demo.Filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.example.demo.Member.PrincipalDetails;
import com.example.demo.Token.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import org.json.simple.JSONObject;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Slf4j
public class LoginFilter  extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private  long jwtExpirationInMs=1;
    private  long refreshExpirationInMs=30;
    private TokenService tokenService;

    public LoginFilter(AuthenticationManager authenticationManager,TokenService tokenService){
        this.authenticationManager=authenticationManager;
        this.tokenService=tokenService;
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

        // 로그인 성공한 유저의 이름 얻어내기
        SecurityContextHolder.getContext().setAuthentication(authResult);
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String username = principalDetails.getUsername();

        // 로그인 성공 시 JWT 토큰 발급
        String jwtToken = tokenService.generateToken(username, jwtExpirationInMs);
        String refreshToken = tokenService.generateToken(username, refreshExpirationInMs);

        // JWT 토큰을 응답 쿠키에 추가
        ResponseCookie jwtCookie = ResponseCookie.from("access_token", jwtToken)
                .path("/")
                .httpOnly(true)
                .maxAge(jwtExpirationInMs * 60)
                .sameSite("none")
                .secure(true)
                .build();
        response.addHeader("Set-Cookie", jwtCookie.toString());

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                .path("/")
                .httpOnly(true)
                .maxAge(refreshExpirationInMs*60)
                .sameSite("none")
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

        LocalDateTime issueDate = LocalDateTime.now();
        long issueCount = 0;
        // 리프레시 토큰 저장
        tokenService.saveRefreshToken(username, refreshToken,issueDate,issueCount);

        // 시큐리티 세션에 인증 주입
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities()));

        // 레디스에 저장된 리프레시 토큰 정보 확인
        Map<String,Object> savedTokenInfo = tokenService.getRefreshTokenInfo(username);
        if (savedTokenInfo != null) {
            // 레디스에 저장된 리프레시 토큰 정보가 있는 경우 로그 출력
            log.info("Refresh Token Info from Redis: {}", savedTokenInfo);
        } else {
            // 레디스에 저장된 리프레시 토큰 정보가 없는 경우 로그 출력
            log.info("Refresh Token Info not found in Redis for user: {}", username);
        }
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
}
