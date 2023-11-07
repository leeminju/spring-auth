package com.sparta.springauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
//Bean등록 메소드 위에 Configuration
@Configuration
public class PasswordConfig { //passwordConfig로 등록
    //Bean으로 등록하고자하는 객체(PasswordEncoder)를 반환하는 메소드위에 @Bean 추가
    @Bean
    public PasswordEncoder passwordEncoder() { // passwordEncoder로 등록  PasswordEncoder->인터페이스
        return new BCryptPasswordEncoder();// PasswordEncoder를 구현한 구현체   (DI 주입)
        //BCrypt : 비밀번호 암호화 해주는 hash 함수 ->현재까지 사용 중인 것들중에 강력한 해시 매커니즘! 많이 사용
        //BCrypt라는 해쉬함수를 사용해 비밀번호를 Encode함! why??? -> 이후 강의
    }
}