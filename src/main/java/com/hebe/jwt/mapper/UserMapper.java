package com.hebe.jwt.mapper;

import com.hebe.jwt.model.UserDTO;
import com.hebe.jwt.model.UserEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {
    int selUsername(String username);
    int selNickname(String nickname);
    int updUser(UserEntity user);
    UserEntity selNameProvider(UserEntity user);
    String selUserPw(int iuser);
    int delUser(int iuser);
    int delData(int iuser);
}