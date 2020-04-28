package com.rahdevelopers.api.oauth.service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.rahdevelopers.api.oauth.clienterest.UsuarioClienteRest;
import com.rahdevelopers.api.oauth.dto.UsuarioDto;

@Service
public class UsuarioServiceImpl implements UsuarioService, UserDetailsService {

	@Autowired
	private UsuarioClienteRest clienteRest;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		String mensajeError = String.format("El usuario: %s no es valido.", username);

		UsuarioDto usuarioDto = Optional.of(this.clienteRest.getByUserName(username))
				.orElseThrow(() -> new UsernameNotFoundException(mensajeError));

		List<GrantedAuthority> authorities = usuarioDto.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.getRoleName())).collect(Collectors.toList());

		return new User(usuarioDto.getUserName(), usuarioDto.getUserPassword(), usuarioDto.getEnabled(), true, true,
				true, authorities);
	}

	@Override
	public UsuarioDto getByUserName(String userName) {
		return this.clienteRest.getByUserName(userName);
	}

}
