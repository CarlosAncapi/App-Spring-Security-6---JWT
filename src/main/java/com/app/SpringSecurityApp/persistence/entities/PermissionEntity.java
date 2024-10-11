package com.app.SpringSecurityApp.persistence.entities;

import jakarta.persistence.*;
import lombok.*;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "permissions")
public class PermissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, updatable = false) // no pueden ser nulos los nombres de los permisos, y tampoco se pueden actualizar después que se crean
    private String name;

}
