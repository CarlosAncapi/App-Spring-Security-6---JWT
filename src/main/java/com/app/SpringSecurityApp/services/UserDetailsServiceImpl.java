package com.app.SpringSecurityApp.services;


import com.app.SpringSecurityApp.persistence.entities.UserEntity;
import com.app.SpringSecurityApp.persistence.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService { // esta clase se encargara de llamar al repositorio para buscar el usuario en la base de datos

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // como el repository devuelve un opcional, en caso de no encontrar el usuario se devolverá una excepción controlada
        UserEntity userEntity = userRepository.findUserEntityByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El usuario " + username + " no existe."));

        // como capture desde la bd un UserEntity, debo convertirlo en un UserDetails
        // para que lo interprete Spring Security, por lo que debo transformarlo en un "User" de Security Core

        // necesito crear una lista de "SimpleGrantedAuthority", ya que Spring Security maneja los permisos/roles
        // con una lista de este tipo ( ejemplo: ROLE_ + ADMIN = ROLE_ADMIN ), por lo que debo transformar los que están en la base de datos en uno que entienda
        // spring security
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        // aquí lo que estoy haciendo es extraer los roles del usuario (objeto) que capturamos desde la base de datos
        // y transformarlos en roles que pueda interpretar Spring security y los añada a los propios que ya tiene
        userEntity.getRoles()
                .forEach(role -> authorityList.add(
                        new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        // ahora que ya Spring security ya interpreta los tipos de roles y los tipos de permisos (porque los cargo en memoria),
        // del objeto UserEntity traído desde la base de datos, ahora puedo retornar "User" de Security Core
        // para que se pueda hacer la validación en la clase con la anotación @Config "SecurityConfig", y lo llamo desde el método "AuthenticationProvider"
        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnabled(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),
                authorityList);
    }
}
