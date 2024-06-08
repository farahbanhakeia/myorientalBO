package com.example.demo.security.jwt;

import com.example.demo.appuser.AppUser;
import io.jsonwebtoken.*;

import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashMap;

@Component
public class JwtProvider {
    //@Value("${jwt.secret}")
    private final static String jwtSecret = "PhreYGtmhCJItR//jLkA9i81YXaUjk8epO0XOG2HFfUjiZ0Ti/FEtP3TqLYv0rE/+XieWLfEKHU65w/FF2qZBg==";
    //@Value("${jwt.expiration}")
    private int jwtExpiration =3600;
    @Lazy
    @Autowired
    private UserDetailsService userDetailsService;

    public String generateToken(Authentication authentication) {
        AppUser userDetails = (AppUser) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration * 1000);
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return Jwts.builder()
                .setSubject(Long.toString(userDetails.getId()))
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key,SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateToken(AppUser userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration * 1000);
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return Jwts.builder()
                .setSubject(Long.toString(userDetails.getId()))
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key,SignatureAlgorithm.HS512)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = extractClaims(token);
        String username = claims.getSubject();

        // Charger les détails de l'utilisateur à partir de son username
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Créer et retourner un objet Authentication
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch ( MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    private Claims extractClaims(String token) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }
}
