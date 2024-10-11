package com.app.SpringSecurityApp.filter;

import com.app.SpringSecurityApp.util.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

public class JwtTokenValidator extends OncePerRequestFilter {
    // OncePerRequestFilter -> por cada petición que se le haga algún endpoint
    // de la aplicación se ejecutará esta clase y validará los tokens

    private JwtUtils jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response,
                                    @NotNull FilterChain filterChain) throws ServletException, IOException {

        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION); // con esto extraigo el encabezado "AUTHORIZATION" de cualquier petición (request) hecha a la aplicación, es decir extraigo el "BEARER TOKEN"

        if (jwtToken != null) {
            jwtToken = jwtToken.substring(7); // esto es porque lo que se captura tiene este formato "bearer ljcbblXNAocbuqqpn.coqbcoqbc.wnqc" entonces con el 7 captura lo que esta después de "bearer " ( después de bearer + el espacio)

            DecodedJWT decodedJWT = jwtUtils.validateToken(jwtToken); // decodificamos el token entregado

            String username = jwtUtils.extractUsername(decodedJWT); // extraigo el username del token entregado
            String stringAuthorities = jwtUtils.getSpecificClaim(decodedJWT,"authorities").asString(); // extraigo las autorizaciones del token

            Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities); // método que devuelve las autorizaciones separadas por comas, ejemplo: "READ,WRITE,DELETE"

            SecurityContext context = SecurityContextHolder.getContext();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities); // En este caso no es necesario una credencial, ya
            context.setAuthentication(authentication); // seteamos la autenticacion al contexto con los datos extraidos del token
            SecurityContextHolder.setContext(context); // le seteamos el contexto al SecurityContextHolder
        }

        filterChain.doFilter(request, response);
    }

}
