package com.example.demo.Token;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final RedisTemplate<String, Object> redisTemplate;

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
}

