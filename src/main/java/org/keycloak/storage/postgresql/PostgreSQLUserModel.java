package org.keycloak.storage.postgresql;

/**
 * Model class representing a user from PostgreSQL database
 */
public class PostgreSQLUserModel {
    
    private final String username;
    private final String email;
    private final String firstName;
    private final String lastName;
    
    public PostgreSQLUserModel(String username, String email, String firstName, String lastName) {
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }
    
    public String getUsername() {
        return username;
    }
    
    public String getEmail() {
        return email;
    }
    
    public String getFirstName() {
        return firstName;
    }
    
    public String getLastName() {
        return lastName;
    }
}