package com.app.SpringSecurityApp.persistence.repositories;

import com.app.SpringSecurityApp.persistence.entities.RoleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends CrudRepository<RoleEntity, Long> {
    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleNames); // Con el nombre estoy declarando una sentencia SQL, solamente me traerá el listado de roles que envío,  por su nombre, los cuales existan en bd, si no existen no me los traerá
}
