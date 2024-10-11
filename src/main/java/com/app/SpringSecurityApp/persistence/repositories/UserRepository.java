package com.app.SpringSecurityApp.persistence.repositories;

import com.app.SpringSecurityApp.persistence.entities.UserEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    // este método busca al usuario en la base de datos usando
    // el nombre del método "find" (encontrar) "UserEntity" (el objeto Entity),
    // "By" por la variable o columna "Username"
    Optional<UserEntity> findUserEntityByUsername(String username);

    // Este otro método realiza lo mismo que el de arriba ( findUserEntityByUsername ) ,
    // pero le pasamos la query de forma explícita
    @Query("SELECT u FROM UserEntity u WHERE u.username = :username")
    Optional<UserEntity> findUser(@Param("username") String username);
}
