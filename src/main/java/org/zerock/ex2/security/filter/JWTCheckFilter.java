package org.zerock.ex2.security.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.ex2.dto.MemberDTO;
import org.zerock.ex2.util.JWTUtil;

import com.google.gson.Gson;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class JWTCheckFilter extends OncePerRequestFilter {

    // Should Not Filter 로 한번 Filtering 작업 검증
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        // PreFlight
        if (request.getMethod().equals("OPTIONS")) {
            return true;
        }

        // 호출 하는 경로를 Check
        String path = request.getRequestURI();

        // Login 이면 Filter 검증 안한다
        if (path.equals("/api/member/login")
                || path.equals("/api/member/refresh")
                || path.startsWith("/api/member/")) {
            return true;
        }

        // http://localhost:8080/login/oauth2/kakao
        // kakao login true
        if (path.startsWith("/login")) {
            return true;
        }

        if (path.startsWith("/oauth2")) {
            return true;
        }

        if (path.startsWith(".ico")) {
            return true;
        }

        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("=========doFilterInternal=========");

        log.info("========doFilterInternal==========");

        String authHeaderStr = request.getHeader("Authorization");

        try {
            // Bearer accestoken...
            String accessToken = authHeaderStr.substring(7);
            Map<String, Object> claims = JWTUtil.validateToken(accessToken);

            log.info("JWT claims: " + claims);

            String email = (String) claims.get("email");
            String pw = (String) claims.get("pw");
            String nickname = (String) claims.get("nickname");
            Boolean social = (Boolean) claims.get("social");
            List<String> roleNames = (List<String>) claims.get("roleNames");

            MemberDTO memberDTO = new MemberDTO(email, pw, nickname, social.booleanValue(), roleNames);

            log.info("-----------------------------------");
            log.info(memberDTO);
            log.info(memberDTO.getAuthorities());

            // 사용자의 정보를 가져와 토큰에 넣어서 시큐리티에서 쓸수있게 전달
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberDTO,
                    pw, memberDTO.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            filterChain.doFilter(request, response);

            // Access Token 문제 Exception
        } catch (Exception e) {

            log.error("JWT Check Error..............");
            log.error(e.getMessage());

            Gson gson = new Gson();
            String msg = gson.toJson(Map.of("error", "ERROR_ACCESS_TOKEN"));

            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();
            printWriter.println(msg);
            printWriter.close();
        }
    }
}
