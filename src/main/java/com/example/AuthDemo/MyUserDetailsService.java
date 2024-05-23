package com.example.AuthDemo;
// MyUserDetailsService.java

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

//@Service
public class MyUserDetailsService implements UserDetailsService {

    // Pretend this is your UserRepository
    // @Autowired
    // private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Load user from the database or any other source
        // For simplicity, I'm assuming user details are retrieved from a UserRepository
        // UserEntity user = userRepository.findByUsername(username);
        // Replace this with your actual logic to fetch user details from database
        if (!username.equals("admin")) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return new User("admin", "admin", new ArrayList<>());
    }
}
