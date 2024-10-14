package com.inexture.sso.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class AuthorizationServerConfig {

//	  @Bean
//	   @Order(Ordered.HIGHEST_PRECEDENCE)
//	   public SecurityFilterChain authorizationSecurityFilterChain(HttpSecurity http) throws Exception {
//	       OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//	       http
//	           .exceptionHandling(
//	               exceptions ->
//	                   exceptions.authenticationEntryPoint(
//	                       new LoginUrlAuthenticationEntryPoint("/login")
//	                   )
//	           );
//
//	       return http.build();
//	   }
	
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain webFilterChainForOauth (HttpSecurity httpSecurity) throws Exception {
		
		
		
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
		httpSecurity.exceptionHandling(auth->auth.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
		
//		httpSecurity
//          .exceptionHandling(
//              exceptions ->
//                  exceptions.authenticationEntryPoint(
//                      new LoginUrlAuthenticationEntryPoint("/login")
//                  )
//          );
		
		return httpSecurity.build();
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		var registerClient=RegisteredClient.withId(UUID.randomUUID().toString())
				.clientName("inexture")
				.clientId("inexture")
				.clientSecret("secret")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
//				.redirectUri("http://localhost:8082/login/oauth2/code/inexture")
				.redirectUri("http://testwebsite.com:8082/login/oauth2/code/inexture")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantTypes(grantType->{
				    grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
				    grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
				    grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
				})
//				.clientSettings(ClientSettings.builder().requireProofKey(true).build())
				.build();
		return new InMemoryRegisteredClientRepository(registerClient);
		
	}
	
	
//	 @Bean
//	   public RegisteredClientRepository registeredClientRepository() {
//	       RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
//	           .clientName("inexture_SSO")
//	           .clientId("inexture")
//			    .clientSecret("secret")
//			    .scope("openid")
//	           .redirectUri("http://localhost:8082/login/oauth2/code/inexture")
//	           .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//	           .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//	           .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//	           .build();
//
//	       return new InMemoryRegisteredClientRepository(demoClient);
//	   }
	
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
}
