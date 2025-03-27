package com.example.bomberos_flask.controllers;
import java.util.List;

public class FingerprintVerificationRequest {
    private List<UserFingerprint> users;

    // Getters y setters
    public List<UserFingerprint> getUsers() {
        return users;
    }

    public void setUsers(List<UserFingerprint> users) {
        this.users = users;
    }

    // Clase interna para representar cada usuario
    public static class UserFingerprint {
        private Long id;
        private String name;
        private String fingerPrint;

        // Getters y setters
        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getFingerPrint() {
            return fingerPrint;
        }

        public void setFingerPrint(String fingerPrint) {
            this.fingerPrint = fingerPrint;
        }
    }
}