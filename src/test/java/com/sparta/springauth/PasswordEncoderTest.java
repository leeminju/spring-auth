package com.sparta.springauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
public class PasswordEncoderTest {
    // 수동등록한 Bean 사용
    @Autowired
    PasswordEncoder passwordEncoder;// 주입 받아 오기

    @Test
    @DisplayName("수동 등록한 passwordEncoder를 주입 받아와 문자열 암호화")
    void test1() {
        String password = "Robbie's password";//현재 password

        // 암호화
        String encodePassword = passwordEncoder.encode(password);//메서드 사용!!
        System.out.println("encodePassword = " + encodePassword);//암호화된 메서드

        String inputPassword = "Robbie";//다른 메서드

        // 복호화를 통해 암호화된 비밀번호와 비교  (입력받은 문자열(평문), 암호환 비밀번호 ) -> matches내부에서 자동으로 비교!
        boolean matches = passwordEncoder.matches(inputPassword, encodePassword);
        System.out.println("matches = " + matches); // 암호화할 때 사용된 값과 다른 문자열과 비교했기 때문에 false
    }
}