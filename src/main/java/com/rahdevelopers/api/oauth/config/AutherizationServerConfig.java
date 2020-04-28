package com.rahdevelopers.api.oauth.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@RefreshScope
@Configuration
@EnableAuthorizationServer
public class AutherizationServerConfig extends AuthorizationServerConfigurerAdapter {

	private BCryptPasswordEncoder passwordEncoder;
	private AuthenticationManager authenticationManager;
	private AditionalInformationTokenConfig AditionalInformationToken;
	private Environment environment;

	@Autowired
	public AutherizationServerConfig(BCryptPasswordEncoder passwordEncoder, AuthenticationManager authenticationManager,
			AditionalInformationTokenConfig aditionalInformationToken, Environment environment) {
		super();
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		AditionalInformationToken = aditionalInformationToken;
		this.environment = environment;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		String cliente = this.environment.getProperty("config.security.ouath.id");
		String secret = this.environment.getProperty("config.security.ouath.secret");

		clients.inMemory().withClient(cliente).secret(this.passwordEncoder.encode(secret)).scopes("read", "write")
				.authorizedGrantTypes("password", "refresh_token").accessTokenValiditySeconds(3600)
				.refreshTokenValiditySeconds(3600);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain
				.setTokenEnhancers(Arrays.asList(this.AditionalInformationToken, this.accessTokenConverter()));

		endpoints.authenticationManager(this.authenticationManager).tokenStore(this.tokenStore())
				.accessTokenConverter(this.accessTokenConverter()).tokenEnhancer(tokenEnhancerChain);
	}

	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(this.accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		String jwtKey = this.environment.getProperty("config.security.ouath.jwt.key");

		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setSigningKey(jwtKey);
		return tokenConverter;
	}

}
