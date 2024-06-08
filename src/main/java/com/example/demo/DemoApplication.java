package com.example.demo;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Key;
import java.util.Base64;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
		Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

		// Afficher la clé en format Base64
		String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
		System.out.println("HMAC-SHA-512 Key: " + base64Key);
	}

}
