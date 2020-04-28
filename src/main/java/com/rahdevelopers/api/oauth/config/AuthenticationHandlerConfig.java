package com.rahdevelopers.api.oauth.config;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationHandlerConfig implements AuthenticationEventPublisher {

	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		 UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		 String userName = userDetails.getUsername();
		 System.out.println(String.format("Autenticación correcta con user: %s", userName));
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		System.out.println(String.format("Error en la autenticación: %s", exception.getMessage()));
	}

}
