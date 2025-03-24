package org.keycloak.storage.postgresql;

/**
 * Model class representing a user from PostgreSQL database
 */
public class PostgreSQLUserModel {
    
    private final String id; // UUID from database
    private final String email; // Used as username
    private final String firstName;
    private final String lastName;
    
    public PostgreSQLUserModel(String id, String email, String firstName, String lastName) {
        this.id = id;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }
    
    public String getId() {
        return id;
    }
    
    public String getUsername() {
        return email; // Email is used as username
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