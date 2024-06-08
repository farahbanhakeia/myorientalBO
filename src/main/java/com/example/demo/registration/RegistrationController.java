package com.example.demo.registration;

import com.example.demo.appuser.AppUser;
import com.example.demo.appuser.AppUserRole;
import com.example.demo.appuser.AppUserService;
import com.example.demo.request.LoginRequest;
import com.example.demo.response.LoginResponse;
import com.example.demo.response.RegistrationResponse;
import com.example.demo.security.jwt.JwtProvider;
import com.example.demo.security.jwt.JwtResponse;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLOutput;
import java.util.HashMap;
import java.util.Map;

//import java.util.UUID;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping(path = "auth/")
@AllArgsConstructor
//@CrossOrigin(origins = "http://localhost:8080", maxAge = 3600, allowCredentials="true")
public class RegistrationController {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private final RegistrationService registrationService;
    @Autowired
    private final AppUserService appUserService;




    @PostMapping("/register")
    public ResponseEntity<RegistrationResponse> register(@RequestBody RegistrationRequest request) {
        String token = registrationService.register(request);
        String link = "http://localhost:8080/api/v1/registration/confirm?token=" + token;

        RegistrationResponse response = new RegistrationResponse();
        response.setToken(token);
        response.setConfirmationLink(link);

        response.setAppUser(new AppUser(
        request.getFirstname(),
        request.getLastname(),
        request.getEmail(),
        request.getPassword(),
                AppUserRole.USER,
                request.getDate_naissance()));
        //return registrationService.register(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(path = "confirm")
    public String confirm(@RequestParam("token") String token) {
        return registrationService.confirmToken(token);
    }

    @PostMapping("authenticate")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        // Authenticate user using Spring Security
        String jwt = null;
        LoginResponse responseLogin = null;
        try {
            Authentication authentication = this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate JWT token (assuming JWT is used for authentication)
            // String jwt = UUID.randomUUID().toString();
            jwt = jwtProvider.generateToken(authentication);
            AppUser userDetails = (AppUser) authentication.getPrincipal();
            responseLogin = new LoginResponse(jwt,userDetails.getAppUserRole());
            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("token", jwt);
        } catch (AuthenticationException e) {
            throw new RuntimeException(e);
        }

        return ResponseEntity.ok(responseLogin);
    }


    @PostMapping("allusers")
    public ResponseEntity<?> getAllUsers(@RequestBody LoginRequest request) {
        String email = request.getEmail();
        String password = request.getPassword();
        try {
            // Authentification de l'utilisateur
            Authentication authentication = this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );

            // Définir le contexte de sécurité
            SecurityContextHolder.getContext().setAuthentication(authentication);
            AppUser userDetails = (AppUser) authentication.getPrincipal();

            // Vérification du rôle de l'utilisateur
            if (userDetails.getAppUserRole() == AppUserRole.ADMIN) {
                return ResponseEntity.ok(appUserService.findAll());
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Vous n'avez pas les droits pour accéder à cette ressource.");
            }
        } catch (AuthenticationException ex) {
            // Gestion des exceptions d'authentification
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Authentification échouée : " + ex.getMessage());
        } catch (Exception ex) {
            // Gestion des autres exceptions
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Une erreur est survenue : " + ex.getMessage());
        }
    }

    @GetMapping("/allu")
    public ResponseEntity<?> getAllUsers(@RequestHeader("Authorization") String token) {
        try {
            // Extraire le token de l'en-tête "Bearer <token>"
            String jwt = token.substring(7);
            if (!jwtProvider.validateToken(jwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token JWT invalide");
            }

            Authentication authentication = jwtProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            AppUser userDetails = (AppUser) authentication.getPrincipal();

            // Vérifier le rôle de l'utilisateur
            if (userDetails.getAppUserRole() == AppUserRole.ADMIN) {
                return ResponseEntity.ok(appUserService.findAll());
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Vous n'avez pas les droits pour accéder à cette ressource.");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Une erreur est survenue : " + ex.getMessage());
        }
}

    @RequestMapping("all")
    public ResponseEntity<?> findAllUsers(){
        System.out.println("hello");
        return new ResponseEntity<>(appUserService.findAll(), HttpStatus.OK);
    }

    @GetMapping("/a")
    public ResponseEntity<?> getAllUser(String token) {
        try {
            // Extraire le token de l'en-tête "Bearer <token>"
            String jwt = token.substring(7);
            if (!jwtProvider.validateToken(jwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token JWT invalide");
            }

            Authentication authentication = jwtProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            AppUser userDetails = (AppUser) authentication.getPrincipal();

            // Vérifier le rôle de l'utilisateur
            if (userDetails.getAppUserRole() == AppUserRole.ADMIN) {
                return ResponseEntity.ok(appUserService.findAll());
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Vous n'avez pas les droits pour accéder à cette ressource.");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Une erreur est survenue : " + ex.getMessage());
        }
    }
}
