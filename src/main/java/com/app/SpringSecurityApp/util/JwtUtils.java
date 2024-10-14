package com.app.SpringSecurityApp.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    //inyectamos el valor desde el archivo properties
    @Value("${security.jwt.key.private}")
    private String privateKey;

    //inyectamos el valor desde el archivo properties
    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    public String createToken(Authentication authentication) {// de aquí extraemos el usuario y contraseña del usuario que ya se autentico ( ingreso usuario y pass correcta )
        String jwtToken = null;
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey); // aquÍ definimos el algoritmo de encriptación (hay varios, ejemplo: HS256, RS384, ES512, ETC.)

            String username = authentication.getPrincipal().toString(); // este usuario que se autenticó y que se encuentra dentro del "SECURITY CONTEXT HOLDER", es decir, el usuario que está autenticándose

            String authorities = authentication.getAuthorities() // estas son los permisos que tiene el usuario que se autenticó
                    .stream()
                    .map(GrantedAuthority::getAuthority) // aquí obtengo las autorizaciones, y las recolecto como String
                    .collect(Collectors.joining(",")); // de esta manera devolvería la cadena "READ,WRITE,CREATE,DELETE"

            jwtToken = JWT.create() // utilizo la librería "com.auth0.jwt.JWT" de java-JWT para crear el token
                    .withIssuer(this.userGenerator) // nuestro usuario que generara el token, el cual está en el properties
                    .withSubject(username) // obtengo al usuario que se autentico previamente
                    .withClaim("authorities", authorities) // aquí le entrego los permisos que tiene el usuario que se autenticó, los cuales se transforman en el PAYLOAD
                    .withIssuedAt(new Date()) // la fecha actual en milisegundos cuando se genera el token
                    .withExpiresAt(new Date(System.currentTimeMillis() + 1800000)) // aquí se le suma el tiempo que quieres que dure el token, en este caso el token quiero que dure 30 minutos, eso en milisegundos son: 1800000
                    .withJWTId(UUID.randomUUID().toString()) // Se le asigna un identificador único a este token, para que no se confunda con algún otro token generado o que se genere a futuro
                    .withNotBefore(new Date(System.currentTimeMillis())) // aquí se le indica al sistema desde que momento empieza a estar activo el token
                    .sign(algorithm); // la firma es con que algoritmo encriptaré el token
        } catch (JWTCreationException exception) {
            exception.printStackTrace();
        }
        return jwtToken; // lo que se retorna es similar a lo que explico más abajo, ejemplo:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        //  +++++++++++++++++++        Ejemplo de un token       +++++++++++++++++++++++

        // el siguiente token se divide en tres partes, estas partes están separadas por un punto.
        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

        // la PRIMERA parte es el header, el cual está codificado en base64  --> "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" que corresponde al siguiente Json
    /*
        {
            "alg": "HS256",
            "typ": "JWT"
        }
     */

        // la SEGUNDA parte es el "PAYLOAD", y en JWT es el "CLAIM", el cual está codificado en base64  --> "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" que corresponde al siguiente Json:
    /*
        {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
        }
     */

        // la TERCERA parte es el "PAYLOAD", y en JWT es el "CLAIM", el cual está encriptado
        // en el algoritmo "HMAC256"  (equivalente a HS256) --> "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    }

    public DecodedJWT validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey); // Se le entrega el tipo de encriptación, en este caso HMAC 256, esta es la misma llave que usamos al crear el token (encriptar) y la rescatamos del properties, para desencriptar el token cuando hagan un próximo llamado a algún endpoint con el token

            JWTVerifier verifier = JWT.require(algorithm) // se le entrega el algoritmo que definí en la línea anterior
                    .withIssuer(this.userGenerator) // además le entrego el nombre del usuario con el que se encripta, el cual está en el properties
                    .build();

            DecodedJWT decodedJWT = verifier.verify(token); // desencripta el token ( verificando si se hizo correctamente la descodificación )
            return decodedJWT; // retorno la decodificación del token
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Token invalid, not Authorized"); //excepción manejada
        }
    }

    public String extractUsername(DecodedJWT decodedJWT){
        return decodedJWT.getSubject().toString();
    }

    public Claim getSpecificClaim(DecodedJWT decodedJWT, String clainName){ // método para extraer un CLAIM en específico, es decir un PAYLOAD en término JWT
        return decodedJWT.getClaim(clainName);
    }

    public Map<String, Claim> returnAllClaims(DecodedJWT decodedJWT){ // método para retornar un mapa de los Claims que estén dentro del token decodificado/desencriptado
        return decodedJWT.getClaims();
    }

}
