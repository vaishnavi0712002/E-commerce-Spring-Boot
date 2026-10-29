package com.jtspringproject.JtSpringProject.dao;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.jtspringproject.JtSpringProject.models.Admin;

@Repository
public class adminDao {

    private final SessionFactory sessionFactory;

    public adminDao(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Transactional
    public Admin getAdminByUsername(String username) {
        Session session = sessionFactory.getCurrentSession();

        return session.createQuery(
                "FROM Admin WHERE username = :username", Admin.class)
                .setParameter("username", username)
                .uniqueResult();
    }

    @Transactional
    public Admin saveAdmin(Admin admin) {
        Session session = sessionFactory.getCurrentSession();
        session.saveOrUpdate(admin);
        return admin;
    }
}