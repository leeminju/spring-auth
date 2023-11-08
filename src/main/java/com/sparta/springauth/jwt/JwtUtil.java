package com.sparta.springauth.jwt;

import com.sparta.springauth.entity.UserRoleEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {
    //JWT 데이터
    // Header KEY 값(쿠키의 Name 값)
    public static final String AUTHORIZATION_HEADER = "Authorization";
    // 사용자 권한 값의 KEY (admin,user)
    public static final String AUTHORIZATION_KEY = "auth";
    // Token 식별자 (Bearer-토큰 value앞에 붙이는 용어, 규칙-해당하는 값은 토큰입니다 알려줌,구분하기 위해 한칸 띄운다)
    public static final String BEARER_PREFIX = "Bearer ";
    // 토큰 만료시간(Expire time)
    private final long TOKEN_TIME = 60 * 60 * 1000L; // 60분(msec단위)

    @Value("${jwt.secret.key}") // Base64 Encode 한 SecretKey <- application.properties에 가져옴
    private String secretKey;
    private Key key;//jwt secret key 담을 객체 -> jwt 암호화 or 복호화해 검증
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;//enum 중 골라서 사용

    // 로그 설정(어플리케이션 동작 동안 프로그램 상태나 동작정보를 시간순으로 기록하는 것) / @slf4j 어노테이션으로도 사용 가능
    public static final Logger logger = LoggerFactory.getLogger("JWT 관련 로그");

    //딱 한번만 받아오는 값 사용시마다 요청을 새로 호출하는 실수 방지하기 위해 사용
    // Why?? JwtUtil() 생성뒤 key에 secrey키 담는다. @PostConstruct는 생성자가 호출된 뒤 사용
    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);//인코딩값 디코딩!
        key = Keys.hmacShaKeyFor(bytes);//바이트값을 변환 후 key에 담는다.
    }

    //1. JWT 생성
    public String createToken(String username, UserRoleEnum role) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(username) // 사용자 식별자값(ID)
                        .claim(AUTHORIZATION_KEY, role) // 사용자 권한
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME)) // 만료 시간
                        .setIssuedAt(date) // 발급일
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                        .compact();//토큰 생성
    }

    // 2. JWT Cookie 에 저장
    public void addJwtToCookie(String token, HttpServletResponse res) {
        try {
            token = URLEncoder.encode(token, "utf-8").replaceAll("\\+", "%20"); // Cookie Value 에는 공백이 불가능해서 encoding 진행

            Cookie cookie = new Cookie(AUTHORIZATION_HEADER, token); // Name-Value
            cookie.setPath("/");

            // Response 객체에 Cookie 추가
            res.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage());
        }
    }

    // 3.받아온 Cookie의 Value인 JWT 토큰 substring
    public String substringToken(String tokenValue) {
        //StringUtils.hasText 공백인지 Null인지 확인
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(7);//"Bearer "부분 짜르기
        }
        logger.error("Not Found Token");
        throw new NullPointerException("Not Found Token");
    }

    //4.JWT 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);//검증
            return true;
        } catch (SecurityException | MalformedJwtException | SignatureException e) {
            logger.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    //5. 토큰에서 사용자 정보 가져오기
    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }
}
