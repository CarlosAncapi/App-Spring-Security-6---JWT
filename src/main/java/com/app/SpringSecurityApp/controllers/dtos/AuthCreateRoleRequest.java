package com.app.SpringSecurityApp.controllers.dtos;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
public record AuthCreateRoleRequest(
        @Size(max = 3, message = "The usser cannot have more than 3 roles") List<String> roleListName) { // no se le pueden entregar más de 3 roles a un usuario
}
