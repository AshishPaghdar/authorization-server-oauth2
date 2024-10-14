package com.inexture.sso.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
    
	@Autowired
	private UserDetailsService userDetailsService;

	
	@Bean
	@Order(2)
	public SecurityFilterChain appSecurity(HttpSecurity httpSecurity)throws Exception {
		httpSecurity.authorizeHttpRequests(request->request.anyRequest().authenticated()).formLogin(Customizer.withDefaults());
		return httpSecurity.build();
		
	}
	
//	@Bean
//	public UserDetailsService detailsService() {
//		var user=User.withUsername("Irshad").password("Test@123").authorities("read").build();
//		return new InMemoryUserDetailsManager(user);
//		
//	}
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	
	
	
	
}
