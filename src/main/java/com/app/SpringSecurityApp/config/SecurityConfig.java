package com.app.SpringSecurityApp.config;

import com.app.SpringSecurityApp.filter.JwtTokenValidator;
import com.app.SpringSecurityApp.services.UserDetailsServiceImpl;
import com.app.SpringSecurityApp.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.sql.SQLOutput;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // me permite trabajar con anotaciones de Spring Security
public class SecurityConfig {

    @Autowired
    private JwtUtils jwtUtils;

    // Para agregar seguridad a mi proyecto necesito una cadena de filtros de seguridad (SecurityFilterChain)
    // Para agregar seguridad a mi proyecto necesito una cadena de filtros de seguridad (SecurityFilterChain)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable()) // CSRF (Cross-Site Request Forgery) es un tipo de protección que impide que un atacante de la web pudiera hacer peticiones maliciosas con las credenciales de un usuario
                .httpBasic(Customizer.withDefaults()) // esta configuración indica que los endpoints por defecto pedirán usuario y contraseña
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // esta configuración es para dejar sin sesión de tiempo un usuario (ejemplo: loguearme en el back y que me permita acceder a los endpoint hasta que se caduce el tiempo de session) , ya que usare tokens
                .authorizeHttpRequests( http -> {
                    // Configurar los endpoint privados
                    http.requestMatchers(HttpMethod.POST, "method/post").hasAnyRole("ADMIN", "DEVELOPER"); // solo un tipo de permiso - este endpoint solo estará disponible para usuarios que tengas permiso de lectura
                    http.requestMatchers(HttpMethod.GET, "method/get").hasAnyRole("INVITED"); //MULTIPLES permisos con hasAnyAuthority
                    http.requestMatchers(HttpMethod.PATCH, "method/patch").hasAuthority("REFACTOR"); // Pueen acceder los que posean permisos "authority" de Refactor
                    http.requestMatchers(HttpMethod.DELETE, "method/delete").hasRole("ADMIN"); // El que tenga un solo tipo de rol
                    http.requestMatchers(HttpMethod.PUT, "method/put").hasAnyRole("ADMIN", "DEVELOPER"); // El que tenga uno de este listado de roles
                    http.requestMatchers(HttpMethod.POST, "auth/**").permitAll(); // se le concede a cualquier solicitante el acceso a los endpoint que estén en la clase AuthenticationController
                    // Configurar el resto de endpoints - No especificados
                    // http.anyRequest().authenticated(); // cualquier usuario que esté autenticado ( que tenga usuario y contraseña correctas ) podrá acceder a cualquier otro endpoint que no esté especificado en las configuraciones de arriba.
                    http.anyRequest().denyAll(); // se le denegará el permiso a cualquier otro endpoint a cualquier usuario o personas sin usuarios (no logueadas)
                })
                .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class) // se necesita que este filtro se realice antes del filtro autenticación o siempre se rechazará la autenticación antes de verificar el token (before = antes)
                .build();
    }

    /*
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable()) // CSRF (Cross-Site Request Forgery) es un tipo de protección que impide que un atacante de la web pudiera hacer peticiones maliciosas con las credenciales de un usuario
                .httpBasic(Customizer.withDefaults()) // esta configuración indica que los endpoints por defecto pedirán usuario y contraseña
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // esta configuración es para dejar sin sesión de tiempo un usuario (ejemplo: loguearme en el back y que me permita acceder a los endpoint hasta que se caduce el tiempo de session) , ya que usare tokens
                // al usar la anotación en esta clase de @EnableMethodSecurity me permite trabajar con anotaciones de Spring security en los controller ( donde habilitamos los endpoint ) con @Preauthorized en las clases controller
                // por lo que no es necesario aquí detallar los tipos de acceso en cada endpoint con : ".authorizeHttpRequests( http -> {})", si no que se hace eso en la clases controller
                .build();
    }
     */

    // Los filtros de seguridad tiene un administrador de autenticaciones (AuthenticationManager)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    // El AuthenticationManager puede tener varios AuthenticationProvider, y estos a su vez se encargan
    // de codificar contraseñas (encriptar y desencriptar) y a su vez de conectarse a una base de datos
    // llamando a UserDetailsService para autenticar usuarios existentes o crearlos

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsServiceImpl userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);  // al traerme los usuarios de la base de datos se interpretan como UserDetailsService
        return provider;
    }

    // esta clase se encarga de encriptar y desencriptar las contraseñas
    @Bean
    public PasswordEncoder passwordEncoder() {
        //return NoOpPasswordEncoder.getInstance(); no ecripta las contraseñas
        return new BCryptPasswordEncoder();
    }

    /*
    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("1234"));
    }

     */
}



