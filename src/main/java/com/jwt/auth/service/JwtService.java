package com.jwt.auth.service;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    
    private String secretKey;

    private Long tokenExpiration;

    private SecretKey getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);


    }

    public String generateToken(Long userId, String username, Long rolId){
        return Jwts.builder()
                .claims(Map.of("userId", userId))
                .claims(Map.of("rolId", rolId))
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + tokenExpiration))

                .signWith(getSignKey())
                .compact();
    }


    public Boolean istokenValid(String token){
        try {
            Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }


    private <T> T extratClaims(String token, Function<Claims, T> resolver){
        final Claims claims = Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return resolver.apply(claims);
    }

    public String extractUsername(String token){
        return extratClaims(token, Claims::getSubject);
    }


    public Long extracxtUserId(String token){
        return extratClaims(token, claims -> claims.get("userId", Long.class));
    }

    public Long extracxtRolId(String token){
        return extratClaims(token, claims -> claims.get("rolId", Long.class));
    }


    public String refreshToken(String token) throws Exception {
        Claims claims;

        try {
            claims = Jwts.parser()
                    .verifyWith(getSignKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
            throw new Exception("Token is expired" + e.getMessage());
        } catch (JwtException e) {
            e.printStackTrace();
            throw new Exception("Token is invalid" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Hubo un error al validar el token" + e.getMessage());
        }

        return generateToken(claims.get("userId", Long.class), claims.getSubject(), claims.get("rolId", Long.class));
    }

}
