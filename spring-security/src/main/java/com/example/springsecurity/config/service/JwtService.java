package com.example.springsecurity.config.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// PROCESO DE VALIDACION JWT (Validate JWT)

@Service
public class JwtService {

    // la secret key se puede generar en la pagina https://www.allkeysgenerator.com/
    // encryption key -> security level como minimo de 256-bit + HEX
    private static final String SECRET_KEY = "3778214125442A472D4B614E645267556B58703273357638792F423F4528482B";
    public String extractUsername(String token){
        // ???????????????
        return extractClaim(token, Claims::getSubject);
    }

    // ?????????????
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                // fecha de inicio del token
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // fecha de expiracion del token = 24 hs + 1000 milisegundos (es a eleccion)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                // como firma le pasamos la signingkey y el tipo de algoritmo de jwt
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // por si necesitamos generar el token sin pasarle como parametro los extra claims
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        // validamos si el username del token es igual al username del userDetails (si existe)
        // y si el token no expiro
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // valida si la fecha de expiracion supera a la fecha de hoy
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // obtenemos la fecha de expiracion del token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                //para crear/generar/descodificar un token necesitamos usar el signingkey (secret) que
                //es usada para crear una firma que se usa para verificar el jwt token en conjunto con el
                //sign-in algorithnm especificado en el JWT header
                //??
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ?????????????????
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
