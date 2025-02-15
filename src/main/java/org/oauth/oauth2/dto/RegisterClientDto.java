package org.oauth.oauth2.dto;

import lombok.Data;

@Data
public class RegisterClientDto {
    private String clientName;
    private String redirectUris;
    private String postLogoutRedirectUris;
    private String scopes;
    private String clientSecret;
}
