package com.example.demo.mapper;


import com.example.demo.model.map.UserMap;

import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 사용자 관련 SQL Mapper 인터페이스 입니다.
 *
 * @author : danyoh
 * @fileName : UserMapper
 * @since : 10/1/24
 */
@Repository
public interface UserMapper {

    Optional<UserMap> login(String userId);

    List<UserMap> selectUserList(UserMap userDto);

}
