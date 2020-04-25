package com.rahdevelopers.api.oauth.clienterest;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.rahdevelopers.api.oauth.dto.UsuarioDto;

@FeignClient(name = "servicio-usuarios")
public interface UsuarioClienteRest {

	@GetMapping("/findbyusername")
	public UsuarioDto getByUserName(@RequestParam String username);
}
