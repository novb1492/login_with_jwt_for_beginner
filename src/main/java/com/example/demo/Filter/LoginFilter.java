package com.example.demo.Filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import org.json.simple.JSONObject;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Slf4j
public class LoginFilter  extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
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
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.info("로그인실패:{}",failed.getMessage());

    }

}
