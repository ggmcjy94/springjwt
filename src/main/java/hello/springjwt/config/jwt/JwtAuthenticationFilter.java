package hello.springjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import hello.springjwt.config.auth.PrincipalDetails;
import hello.springjwt.dto.LoginRequestDto;
import hello.springjwt.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음 .
//login 요청 후 Username password 전송하면 ( post )
//UsernamePasswordAuthenticationFilter 동작함 
// 지금 현재는 form login 을 disable 을 해서 
// JwtAuthenticationFilter security 에 등록 해줘야 함

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("attemptAuthentication 실행 되는 부분 로그인 시도중");

        System.out.println("JwtAuthenticationFilter : 진입");

        // request에 있는 username과 password를 파싱해서 자바 Object로 받기
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;
        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("JwtAuthenticationFilter : "+loginRequestDto);

        // 유저네임패스워드 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequestDto.getUsername(),
                        loginRequestDto.getPassword());

        System.out.println("JwtAuthenticationFilter : 토큰생성완료");

        // authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
        // loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
        // UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
        // UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
        // Authentication 객체를 만들어서 필터체인으로 리턴해준다.

        // Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
        // Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
        // 결론은 인증 프로바이더에게 알려줄 필요가 없음.
        Authentication authentication =
                authenticationManager.authenticate(authenticationToken);

        PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("Authentication : "+principalDetailis.getUser().getUsername());
        return authentication;




//        //1. username, password 받아서
//        try {
////            BufferedReader br = request.getReader();
////            String input = null;
////            while ((input = br.readLine()) != null) {
////                log.info("input = {} ", input);
////            }
////            log.info("request.getInputStream = {}", request.getInputStream().toString());
//            ObjectMapper om = new ObjectMapper();
//            User user = om.readValue(request.getInputStream(), User.class);
//            log.info("user = {}", user);
//            UsernamePasswordAuthenticationToken authenticationToken =
//                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()); //token 생성
//
//            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication 이 리턴됨.
//            // DB에 있는 username 과 password 가 일치된다.
//            Authentication authentication =
//                    authenticationManager.authenticate(authenticationToken);
//
//            // authentication 객체가 session 영역에 저장됨. --> 로그인이 되었다는 뜻
//            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//            log.info("로그인 완료됌 : principalDetails.getUsername() = {}", principalDetails.getUser().getUsername()); //로그인 정상적으로 됌
//
//            // authentication 객체가 session영역에 저장을 해야하고 그방법이 return 해주면됨.
//            //리턴의 이유는 권한 관리를 security가 대신 해주기 떄문에 편하려고 하는거임.
//            // 굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리떄문에 session 넣어줌
//            return authentication;
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        log.info("==================================================================");
//        //2. 정상인지 로그인 시도를 해본다. attemptAuthentication 로 로그인 시도를 하면
//        // PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행
//        //3. principalDetails 를 세션에 담고 (권한 관리를 위해서)
//        //4. jwt 토큰을 만들어서 응답해주면 됌
//        return null;
    }

    // attemptAuthentication 실행후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // jwt 토큰을 만들어서 request 요청한 사용자에세 jwt 토큰을 response 해주면 됌
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("success ful Authenticaion 실행 인증 완료");
        PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principalDetailis.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetailis.getUser().getId())
                .withClaim("username", principalDetailis.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
        
    }
}
