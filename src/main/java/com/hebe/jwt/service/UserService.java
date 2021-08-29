package com.hebe.jwt.service;

import com.hebe.jwt.mapper.UserMapper;
import com.hebe.jwt.model.UserDTO;
import com.hebe.jwt.model.UserEntity;
import com.hebe.jwt.repository.UserRepository;
import com.hebe.jwt.util.CookieUtil;
import com.hebe.jwt.util.JwtUtil;
import com.hebe.jwt.util.RedisUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.File;

@Service
public class UserService {
    @Autowired private UserRepository userRepository;
    @Autowired private UserMapper userMapper;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private CookieUtil cookieUtil;
    @Autowired private RedisUtil redisUtil;

    public int selUsername(String username) {
        int result = userMapper.selUsername(username);
        return result;
    }

    public int selNickname(String nickname) {
        System.out.println("닉네임 검사 : " + nickname);
        int result = userMapper.selNickname(nickname);
        return result;
    }

    public void join(UserEntity user) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setIntroduction("한 줄 소개");
        user.setProfileimg("/img/common/profile.png");
        user.setProvider("HEBE");
        userRepository.save(user);
    }

    public UserEntity login(UserDTO user, HttpServletResponse res) {
        System.out.println("AuthService 진입!");
        UserEntity userEntity = userRepository.findByUsername(user.getUsername());
        String token = jwtUtil.generateToken(userEntity);
        String refreshJwt = jwtUtil.generateRefreshToken(userEntity);
        Cookie accessToken = cookieUtil.createCookie(JwtUtil.ACCESS_TOKEN_NAME, token);
        Cookie refreshToken = cookieUtil.createCookie(JwtUtil.REFRESH_TOKEN_NAME, refreshJwt);
        redisUtil.setDataExpire(refreshJwt, userEntity.getUsername(), JwtUtil.REFRESH_TOKEN_VALIDATION_SECOND);
        res.addCookie(accessToken);
        res.addCookie(refreshToken);
        return userEntity;
    }

    public String fileToString(MultipartFile file, int iuser) {
        String path = "C:\\study\\practice\\springboot\\HEBE-prac\\real\\HEBE-app_9\\public\\img\\user\\" + iuser + "\\profile";

        File dir = new File(path);

        if(!dir.exists()) { dir.mkdirs(); }

        File target = new File(path + "/" + iuser + ".jpg");

        try { file.transferTo(target); }
        catch (Exception e) { e.printStackTrace(); }

        return "/img/user/" + iuser + "/profile/" + iuser + ".jpg";
    }

    public void profileMod(UserEntity user) {
        userMapper.updUser(user);
    }
}