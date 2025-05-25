package com.libcode.crud.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class GrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Busca roles en diferentes claims posibles
        List<String> roles = jwt.getClaimAsStringList("https://agat.com/roles");
        if (roles == null) {
            roles = jwt.getClaimAsStringList("https://loscalcenteros/roles");
        }
        if (roles == null) {
            roles = jwt.getClaimAsStringList("roles");
        }
        
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }
        
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
            .collect(Collectors.toList());
    }
}