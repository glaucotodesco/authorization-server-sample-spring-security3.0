package com.abutua.authorizationserversample.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.abutua.authorizationserversample.entities.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{
}