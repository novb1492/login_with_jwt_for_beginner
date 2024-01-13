package com.example.demo.Filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.Member.PrincipalDetails;
import com.example.demo.Token.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@Slf4j
public class AuthorizationFilter extends BasicAuthenticationFilter {

    private TokenService tokenService;

    public AuthorizationFilter(AuthenticationManager authenticationManager,TokenService tokenService) {
        super(authenticationManager);
        this.tokenService = tokenService;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증필터 입장");
        // 현재 요청된 URL 확인
        String requestURI = request.getRequestURI();
        log.info("Request URI: {}", requestURI);

        // 허용되는 URL 패턴 정의
        String allowedPattern = "/pass"; // 예시로 "/public/"로 시작하는 URL은 인증 필터를 통과시킴

        // 허용되는 URL 패턴인 경우 통과
        if (requestURI.startsWith(allowedPattern)) {
            log.info("허용되는 URL, 필터 통과");
            chain.doFilter(request, response);
            return;
        }
        log.info("허용되는 되지않는 URL, 검증시작");
        // 쿠키에서 엑세스 토큰 추출
        String accessToken = extractAccessTokenFromCookie(request);
        log.info("accessToken:{}",accessToken);
        if (accessToken != null) {
            // 엑세스 토큰에서 사용자 ID 추출
            String username = tokenService.getValue(accessToken);
            log.info("username:{}",username);

            // 시큐리티 세션에 인증 주입
            PrincipalDetails principalDetails =new PrincipalDetails(username,null);
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities()));

            if(username==null){
                set403(response);
            }
            chain.doFilter(request, response);
            return;
        }
        log.info("accessToken을 찾을 수없습니다");
        set403(response);
    }
    private void set403(HttpServletResponse response) throws IOException {
        // 검증 실패 응답 설정
        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403 Forbidden 상태 코드를 설정

        // 실패 메시지를 JSON 형식으로 응답에 추가
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "Authentication failed");
        errorResponse.put("message", "need re login");

        response.setContentType("application/json");
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));

        response.getWriter().flush();
    }
    private String extractAccessTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

}
