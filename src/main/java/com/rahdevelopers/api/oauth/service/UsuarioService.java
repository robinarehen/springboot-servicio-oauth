package com.rahdevelopers.api.oauth.service;

import com.rahdevelopers.api.oauth.dto.UsuarioDto;

@FunctionalInterface
public interface UsuarioService {

	public UsuarioDto getByUserName(String userName);
}
