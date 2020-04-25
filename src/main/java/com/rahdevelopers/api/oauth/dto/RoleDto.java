package com.rahdevelopers.api.oauth.dto;

import java.util.List;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RoleDto {

	private Long ID;
	private String roleName;
	private List<UsuarioDto> usuarios;
}
