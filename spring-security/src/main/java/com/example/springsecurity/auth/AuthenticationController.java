package com.example.springsecurity.auth;

import com.example.springsecurity.auth.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/registro")
    public ResponseEntity<AuthenticationResponse> registro(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authenticationService.registro(request));
    }

    @PostMapping("/autenticacion")
    public ResponseEntity<AuthenticationResponse> autenticacion(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.autenticacion(request));
    }

}
