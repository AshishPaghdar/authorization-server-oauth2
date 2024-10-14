package com.inexture.sso.repo;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inexture.sso.entity.User;

public interface UserRepository extends JpaRepository<User,UUID>{
	User findByUsername(String username);
}
