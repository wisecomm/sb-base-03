package com.example.demo.service;

import com.example.demo.mapper.UserMapper;
import com.example.demo.model.map.UserMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserMapper userMapper;

    public Optional<UserMap> getUserById(String userId) {
        return userMapper.login(userId);
    }

}