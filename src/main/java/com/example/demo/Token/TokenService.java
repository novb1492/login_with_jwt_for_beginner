package com.example.demo.Token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final RedisTemplate<String, Object> redisTemplate;
    private  String jwtSecret="jwtSecret";

    public String generateToken(String username, long expiration) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(jwtSecret);
            Date expiryDate = new Date(System.currentTimeMillis() + 1000*expiration*60);

            return JWT.create()
                    .withSubject(username)
                    .withIssuedAt(new Date())
                    .withExpiresAt(expiryDate)
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            throw new RuntimeException("Error creating JWT token", e);
        }
    }

    public void saveRefreshToken(String username, String refreshToken, LocalDateTime issueDate, long issueCount) {
        // TokenInfo 객체 생성
        Map<String,Object> tokenInfo = new HashMap<>();
        tokenInfo.put("id",username);
        tokenInfo.put("refreshToken",refreshToken);
        tokenInfo.put("issueDate",issueDate.toString());
        tokenInfo.put("issueCount",issueCount);
        // 여기에서 username을 사용하여 리프레시 토큰 정보를 객체로 직렬화하여 저장
        redisTemplate.opsForHash().put("refreshToken"+username, username,tokenInfo);
        // 만료 시간 설정 (예: 1시간)
        redisTemplate.expire("refreshToken" + username, 1, TimeUnit.HOURS);
    }

    public Map<String,Object> getRefreshTokenInfo(String username) {
        // 여기에서 username을 사용하여 리프레시 토큰 정보를 역직렬화하여 추출
        return (Map<String,Object>) redisTemplate.opsForHash().get("refreshToken" + username,username);
    }

    public String getValue(String jwtToken){
        try {
            // JWT 검증을 위한 알고리즘 설정
            Algorithm algorithm = Algorithm.HMAC512(jwtSecret);

            // JWT 검증기 생성
            JWTVerifier verifier = JWT.require(algorithm).build();

            return verifier.verify(jwtToken).getSubject();

        } catch (Exception e) {
            // 토큰이 유효하지 않거나 디코딩에 실패한 경우
            e.printStackTrace();
            log.error("토큰이 유요하지 않습니다");
            return null;
        }
    }

}

