package com.inexture.sso.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.inexture.sso.entity.Role;
import com.inexture.sso.entity.User;
import com.inexture.sso.repo.UserRepository;

import org.springframework.security.core.authority.SimpleGrantedAuthority;



@Service
public class CustomUserDetails implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username);
		if (user != null) {
			return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
					mapRolesAndPermissionsToAuthorities(user.getRoles()));

		} else {
			throw new UsernameNotFoundException("Invalid username or password.");
		}
	}

	private Collection<? extends GrantedAuthority> mapRolesAndPermissionsToAuthorities(Collection<Role> roles) {
		return roles.stream().flatMap(role -> {
			// Map role to authorities
			List<GrantedAuthority> roleAuthorities = List.of(new SimpleGrantedAuthority("ROLE_" + role.getName()));

			// Map permissions to authorities
			List<GrantedAuthority> permissionAuthorities = role.getPermission().stream()
					.map(permission -> new SimpleGrantedAuthority(permission.getName())).collect(Collectors.toList());

			// Combine both role and permission authorities
			List<GrantedAuthority> combinedAuthorities = new ArrayList<>(roleAuthorities);
			combinedAuthorities.addAll(permissionAuthorities);
			return combinedAuthorities.stream();
		}).collect(Collectors.toList());
	}


}
