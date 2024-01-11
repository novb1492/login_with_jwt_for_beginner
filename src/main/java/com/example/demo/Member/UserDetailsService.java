package com.example.demo.Member;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<String> tempInfo = tempInfo(username);
        return new PrincipalDetails(username, tempInfo.get(1));
    }
    private List<String>tempInfo(String username){
        List<String> tempInfo = new ArrayList<>();
        if(username.equals("kim")){
            tempInfo.add("kim");
            tempInfo.add("$2a$12$qMfj1gc1MQnJReMJwq1zH.u85uqp/0V3Ij/LqBdeITiJmNcwyjwfS");
        }else{
            tempInfo.add("kim2");
            tempInfo.add("$2a$12$KxYh2x/YI4TY5qYuwicYKe4Kr7fPlA7aLqvmE18bJaJ/2fRIPa95.");
        }
        return tempInfo;
    }
}
