package com.example.springbootjwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;

@Service
public class SecurityService {

    private static final String SECRET_kEY = "qefqefqafdaf1fesdfaff31fqfgfbgbxfvcvdhtwvzxcasd";

    //로그인 서비스 보낼때 같이 내보냄
    public String createToken(String subject, long expTime){
        if(expTime<=0){
            throw  new RuntimeException("토큰 만료시간이 다되었습니다");
        }

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(SECRET_kEY);
        Key signingKey = new SecretKeySpec(secretKeyBytes, signatureAlgorithm.getJcaName());

        return Jwts.builder()
                .setSubject(subject)
                .signWith(signingKey, signatureAlgorithm)
                .setExpiration(new Date(System.currentTimeMillis() + expTime))
                .compact();
    }
    //validation token
    //@return boolean
    public String getSubject (String token){
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_kEY))
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }
}
