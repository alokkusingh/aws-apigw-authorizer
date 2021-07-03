package com.alok.cloud.aws.apigw.authorizer.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;


public class JwtUtils {

    private static final String SECRET = "aloktest";

    public static String getUserNameFromToken(String token) {
        System.out.println("Validating User Token: " + token);
        return getClaimFromToken(token, Claims::getSubject);
    }

    private static <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(
                getAllClaimsFromToken(token)
        );
    }

    private static Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }
}
