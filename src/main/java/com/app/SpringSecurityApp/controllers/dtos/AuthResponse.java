package com.app.SpringSecurityApp.controllers.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"username", "message", "jwt", "status"})
public record AuthResponse (String username,
                            String message,
                            String jwt,
                            boolean status){

}
