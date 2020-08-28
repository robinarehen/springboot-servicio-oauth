package com.rahdevelopers.api.oauth.config;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AuthenticationHandlerConfig implements AuthenticationEventPublisher {

	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		 UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		 String userName = userDetails.getUsername();
		 log.info("Autenticación correcta con user: {}", userName);
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		log.error("Error en la autenticación: {}", exception.getMessage());
	}

}
