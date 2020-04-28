package com.rahdevelopers.api.oauth.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import com.rahdevelopers.api.oauth.dto.UsuarioDto;
import com.rahdevelopers.api.oauth.service.UsuarioService;

@Component
public class AditionalInformationTokenConfig implements TokenEnhancer {

	@Autowired
	private UsuarioService usuarioService;

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		// TODO Auto-generated method stub
		String userName = authentication.getName();
		UsuarioDto usuarioDto = this.usuarioService.getByUserName(userName);

		Map<String, Object> information = new HashMap<>();

		information.put("nombre", usuarioDto.getNombre());
		information.put("apellidos", usuarioDto.getApellidos());
		information.put("email", usuarioDto.getEmail());

		DefaultOAuth2AccessToken defaultAccessToken = (DefaultOAuth2AccessToken) accessToken;
		defaultAccessToken.setAdditionalInformation(information);

		return accessToken;
	}

}
