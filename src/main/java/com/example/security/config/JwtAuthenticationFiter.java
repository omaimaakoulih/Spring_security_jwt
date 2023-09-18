package com.example.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFiter extends OncePerRequestFilter { // pour que cette class soit executer a chaque fois qu'on a une request

    private final JwtService jwtService;

    public JwtAuthenticationFiter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // the filterChain is the chain of responsibility design pattern ==> to invoke the next filter in the chain
        final String authHeader = request.getHeader("Authorization"); // to get the jwt token from the request header
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response); // pass to the next filter
            return;
        }
        jwt = authHeader.substring(7);// after the Word "Bearer "
        userEmail = jwtService.extractUserEmail(jwt); // extract the user Email from the jwt token
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){ // the second condition is to verify if the user is not connected yet

        }

    }
}
