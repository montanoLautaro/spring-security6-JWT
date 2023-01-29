package com.example.springsecurity.config;

import com.example.springsecurity.config.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


//se extiende de OncePerRequestFilter para que funcione
//de filtro ante cualquier request por lo menos una vez

@Component
@RequiredArgsConstructor
// RequiredArgsConstructor crea un constructor usando las variables del tipo final
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    // @NoNull para no permitir valores nulos en esos parametros
    // este metodo es el primero que se ejecuta cuando se envia una peticion
    @Override
    protected void doFilterInternal(
            //intercepta la request como parametro
           @NonNull HttpServletRequest request,
            //provee una respuesta de esa request
            @NonNull HttpServletResponse response,
            //el filterchain creado del config
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // ?????
        final String authHeader = request.getHeader("Authorization");

        // para chequear el token JWT
        final String jwt;

        final String userEmail;

        // si no empieza con la keyword bearer + space o es nulo
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            // no queremos seguir con la autenticacion ya que devolvemos una respuesta 403
            return;
        }
        // extraer el token del authHeader
        // 7 porque empieza con la palabra bearer + el espacio = 7
        jwt = authHeader.substring(7);

        // extraer el nombre de usuario o mail con el proceso de validacion jwt
        userEmail = jwtService.extractUsername(jwt);
        // si el nombre de usuario no es nulo y no esta autenticado
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if(jwtService.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // SecurityContextHolder donde spring guarda los details de el usuario autenticado
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
