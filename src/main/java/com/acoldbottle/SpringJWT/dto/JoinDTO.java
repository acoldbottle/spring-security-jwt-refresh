package com.acoldbottle.SpringJWT.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JoinDTO {

    private String username;
    private String password;

    public JoinDTO() {

    }
}
