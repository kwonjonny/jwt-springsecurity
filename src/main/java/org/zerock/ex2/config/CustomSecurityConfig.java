package org.zerock.ex2.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.zerock.ex2.security.filter.JWTCheckFilter;
import org.zerock.ex2.security.handler.APILoginSuccessHandler;
import org.zerock.ex2.security.handler.CustomAccessDeniedHandler;

import java.util.Arrays;

@Configuration
@Log4j2
@RequiredArgsConstructor
@EnableMethodSecurity
public class CustomSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("=========Security==========");

        // cors 설정
        http.cors(config -> config.configurationSource(corsConfigurationSource()));

        // scrf 사용안함
        http.csrf((config -> config.disable()));

        // 로그인 설정이지만 화면은 X POSTMAN으로 테스트
        // 로그인 후 successHandler작동
        http.formLogin(config -> {
            config.loginPage("/api/member/login");

            // POSTMAN 시 빈화면 => 사용자 정보들을 다 가지고온다.
            config.successHandler(new APILoginSuccessHandler());
        });

        http.exceptionHandling(config -> config.accessDeniedHandler(new CustomAccessDeniedHandler()));

        // API서버 => 세션 쿠키 사용안함
        http.sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 로그인 전에 JWTCheckFilter 사용
        http.addFilterBefore(new JWTCheckFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // CrossOrigin 사용 안해도 된다.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
