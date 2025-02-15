package org.oauth.oauth2.dto;

import lombok.Data;

@Data
public class RegisterUserDto {

    private String email;

    private String name;

    private String phone;

    private String password;

    private String password_confirm;

    public boolean pwCheck(){
        return password.equals(password_confirm);
    }
}
