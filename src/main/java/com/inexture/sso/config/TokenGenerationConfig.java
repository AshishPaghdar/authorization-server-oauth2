package com.inexture.sso.config;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import com.inexture.sso.entity.User;
import com.inexture.sso.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class TokenGenerationConfig {
	@Autowired
	private UserRepository userRepository;

	@Bean
	public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException{
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		var keys=keyPairGenerator.generateKeyPair();
		var publicKey = (RSAPublicKey) keys.getPublic();
	    var privateKey = (RSAPrivateKey) keys.getPrivate();
	    RSAKey rsaKey = new RSAKey.Builder(publicKey)
	            .privateKey(privateKey)
	            .keyID(UUID.randomUUID().toString())
	            .build();
	        JWKSet jwkSet = new JWKSet(rsaKey);
	        System.out.println("SuccessFully Token Generated ");
	        return new ImmutableJWKSet<>(jwkSet);
	}
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
	  return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	
	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
	   JWKSource<SecurityContext> jwkSource,
	   OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer
	) {
	   NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
	   JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
	   jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
	   OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
	   OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

	   return new DelegatingOAuth2TokenGenerator(
	       jwtGenerator, accessTokenGenerator, refreshTokenGenerator
	   );
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
	   return context -> {
	       UserDetails principal = (UserDetails) context.getPrincipal().getPrincipal();

	       context.getClaims()
	           .claim(
	               "authorities",
	               principal.getAuthorities().stream()
	                   .map(GrantedAuthority::getAuthority)
	                   .collect(Collectors.toSet())
	           );
		   context.getClaims().claim("email","kadivalirshad16@gmail.com");
		   Map<String,Object> userInfo = this.generateClaims(
				   context.getPrincipal().getName());
		   context.getClaims().claims(claims ->
				   claims.putAll(userInfo));
	   };
	}

	private Map<String,Object> generateClaims(String name) {
		User user = userRepository.findByUsername(name);
		Map<String,Object> listOfUser=new HashMap<>();
		listOfUser.put("email",user.getUsername()+"@gmail.com");
		listOfUser.put("mobile_number",user.getPhone_number());
		listOfUser.put("FullName",user.getFirstName()+" "+user.getLastName());
		return listOfUser;
	}


	
}
