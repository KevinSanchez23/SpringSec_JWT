package com.Kuro.SpringSec_JWT.service;

import com.Kuro.SpringSec_JWT.model.User;
import com.Kuro.SpringSec_JWT.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final JWTService jwtService;
    AuthenticationManager authManger;
    private final UserRepository userRepository;

    public UserService(JWTService jwtService,  UserRepository userRepository, AuthenticationManager authManger) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.authManger = authManger;
    }

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public User register(User user){
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public String verify (User user){
        Authentication authentication = authManger.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        if(authentication.isAuthenticated()){
            return jwtService.generateToken(user.getUsername());
        }else{
            return "fail";
        }
    }

}
