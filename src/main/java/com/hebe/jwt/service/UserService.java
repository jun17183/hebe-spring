package com.hebe.jwt.service;

import com.hebe.imgUpload.FileManager;
import com.hebe.imgUpload.UploadImageS3;
import com.hebe.jwt.mapper.UserMapper;
import com.hebe.jwt.model.UserEntity;
import com.hebe.jwt.repository.UserRepository;
import com.hebe.jwt.util.CookieUtil;
import com.hebe.jwt.util.JwtUtil;
import com.hebe.jwt.util.RedisUtil;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    @Autowired private UserRepository userRepository;
    @Autowired private UserMapper userMapper;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private CookieUtil cookieUtil;
    @Autowired private RedisUtil redisUtil;
    @Autowired private AuthenticationManager authenticationManager;
    @Autowired private PasswordEncoder passwordEncoder;

    @Autowired private FileManager fileManager;
    @Autowired private UploadImageS3 uploadImageS3;

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

    public UserEntity login(UserEntity user, HttpServletResponse res) {
        UserEntity userEntity = userMapper.selNameProvider(user);
        jwtCookie(userEntity, res);
        return userEntity;
    }

    public UserEntity apiLogin(UserEntity user, HttpServletResponse res) {
        UserEntity userEntity = userMapper.selNameProvider(user);

        if (userEntity == null) {
            String uuid = UUID.randomUUID().toString().toUpperCase();
            String nickname = uuid.substring(uuid.length() - 6);

            UserEntity newUser = new UserEntity();
            newUser.setUsername(user.getUsername());
            newUser.setPassword(passwordEncoder.encode(user.getPassword()));
            newUser.setProfileimg(user.getProfileimg());
            newUser.setNickname(nickname);
            newUser.setIntroduction("한 줄 소개");
            newUser.setProvider(user.getProvider());

            userRepository.save(newUser);
            userEntity = newUser;
        }

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        jwtCookie(userEntity, res);

        return userEntity;
    }

    public void jwtCookie(UserEntity userEntity, HttpServletResponse res) {
        String token = jwtUtil.generateToken(userEntity);
        String refreshJwt = jwtUtil.generateRefreshToken(userEntity);
        Cookie accessToken = cookieUtil.createCookie(JwtUtil.ACCESS_TOKEN_NAME, token);
        Cookie refreshToken = cookieUtil.createCookie(JwtUtil.REFRESH_TOKEN_NAME, refreshJwt);
        redisUtil.setDataExpire(refreshJwt, userEntity.getUsername(), JwtUtil.REFRESH_TOKEN_VALIDATION_SECOND);
        res.addCookie(accessToken);
        res.addCookie(refreshToken);
    }

    public String fileToString(MultipartFile mf, int iuser) {
        String ext = FilenameUtils.getExtension(mf.getOriginalFilename());
        String saveFileName = UUID.randomUUID().toString() + "." + ext;

        String filePath = "img/profile/" + iuser;

        File uploadFile = null;
        try {
            Optional<File> uploadFileOpt = fileManager.convertMultipartFileToFile(mf);
            if (uploadFileOpt.isEmpty()) {
                System.out.println("파일 변환에 실패했습니다.");
            }
            uploadFile = uploadFileOpt.get();

            // 파일 업로드
            String saveFilePath = uploadImageS3.upload(uploadFile, filePath, saveFileName);

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("파일을 업로드 하던 중 에러가 발생했습니다.");
        } finally {
            // 파일 삭제
            if (uploadFile != null) {
                uploadFile.delete();
            }
        }

        return "/" + filePath + "/" + saveFileName;
    }

    public void profileMod(UserEntity user) {
        userMapper.updUser(user);
    }

    public int selUserPw(Map<String,String> user) {
        int result = 0;
        int iuser = Integer.parseInt(user.get("iuser"));
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String selPw = userMapper.selUserPw(iuser);
        if(passwordEncoder.matches(user.get("password"),selPw) == true) {
            userMapper.delData(iuser);
            result = userMapper.delUser(iuser);
        }
        return result;
    }
}