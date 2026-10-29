package com.jtspringproject.JtSpringProject.services;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.jtspringproject.JtSpringProject.dao.adminDao;
import com.jtspringproject.JtSpringProject.models.Admin;

@Service
public class adminService {

    private final adminDao adminDao;
    private final PasswordEncoder passwordEncoder;

    public adminService(adminDao adminDao, PasswordEncoder passwordEncoder) {
        this.adminDao = adminDao;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public Admin getAdminByUsername(String username) {
        return adminDao.getAdminByUsername(username);
    }

    @Transactional
    public Admin saveAdmin(Admin admin) {
        if (admin.getPassword() != null
                && !isPasswordEncoded(admin.getPassword())) {
            admin.setPassword(passwordEncoder.encode(admin.getPassword()));
        }

        if (admin.getRole() == null || admin.getRole().isBlank()) {
            admin.setRole("ROLE_ADMIN");
        }

        return adminDao.saveAdmin(admin);
    }

    private boolean isPasswordEncoded(String password) {
        return password != null
                && (password.startsWith("$2a$")
                || password.startsWith("$2b$")
                || password.startsWith("$2y$"));
    }
}