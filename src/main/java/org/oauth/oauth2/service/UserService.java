package org.oauth.oauth2.service;

import org.oauth.oauth2.dto.RegisterUserDto;
import org.oauth.oauth2.entity.User;
import org.oauth.oauth2.repository.UserRepository;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder){
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Transactional
    public User registerUser(RegisterUserDto dto){
        if(dto.getEmail().isBlank()||dto.getName().isBlank()||dto.getPassword().isBlank()){
            throw new IllegalArgumentException("공란이 존재합니다.");
        }
        if (!dto.pwCheck()){
            throw new IllegalArgumentException("비밀번호 재확인 불일치");
        }
        if (userRepository.findByEmail(dto.getEmail()).isPresent()){
            throw new IllegalArgumentException("이미 존재하는 사용자입니다.");
        }
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        user.setPhone(dto.getPhone());
        user.setName(dto.getName());
        return userRepository.save(user);
    }
}
