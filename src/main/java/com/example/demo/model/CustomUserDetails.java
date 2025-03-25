package com.example.demo.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;

import com.example.demo.model.map.UserMap;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import lombok.Getter;

@Getter
public class CustomUserDetails implements UserDetails {
    private UserMap user;
    private Map<String, Object> attribute;

    /* 일반 로그인 생성자 */
    public CustomUserDetails(UserMap user) {
        this.user = user;
    }

    private GrantedAuthority getAuthority(String role) {
        return new SimpleGrantedAuthority(role);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(getAuthority(user.getUserSt()));

        return authorityList;
    }

    @Override
    public String getPassword() {
        return user.getUserPw();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
