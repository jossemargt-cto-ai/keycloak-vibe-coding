package org.keycloak.storage.postgresql;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

/**
 * Manages PostgreSQL database connections and queries for user federation
 */
public class PostgreSQLConnectionManager {
    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLConnectionManager.class);
    
    private final String jdbcUrl;
    private final Properties connectionProps;
    
    private final String usersTableName;
    private final String idField; // UUID field
    private final String emailField; // Used as username
    private final String passwordField;
    private final String firstNameField;
    private final String lastNameField;
    
    public PostgreSQLConnectionManager(String jdbcUrl, String username, String password,
                                      String usersTableName, String idField, String passwordField, 
                                      String emailField, String firstNameField, String lastNameField) {
        this.jdbcUrl = jdbcUrl;
        this.connectionProps = new Properties();
        this.connectionProps.put("user", username);
        this.connectionProps.put("password", password);
        
        this.usersTableName = usersTableName;
        this.idField = idField;
        this.passwordField = passwordField;
        this.emailField = emailField;
        this.firstNameField = firstNameField;
        this.lastNameField = lastNameField;
    }
    
    /**
     * Creates and returns a database connection
     */
    public Connection getConnection() throws SQLException {
        try {
            return DriverManager.getConnection(jdbcUrl, connectionProps);
        } catch (SQLException e) {
            logger.error("Error connecting to PostgreSQL database", e);
            throw e;
        }
    }
    
    /**
     * Validate user credentials using bcrypt
     * 
     * @param email The email to validate (used as username)
     * @param password The password to check against the stored hash
     * @return true if credentials are valid, false otherwise
     */
    public boolean validateUser(String email, String password) {
        String sql = "SELECT " + passwordField + " FROM " + usersTableName + 
                     " WHERE " + emailField + " = ?";
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedPasswordHash = rs.getString(1);
                    
                    // Verify the password using bcrypt
                    BCrypt.Result result = BCrypt.verifyer().verify(
                        password.toCharArray(), 
                        storedPasswordHash
                    );

                    return result.verified;
                }
            }
        } catch (SQLException e) {
            logger.error("Error validating user", e);
        }
        
        return false;
    }
    
    /**
     * Gets user by username (which is email in our case)
     */
    public PostgreSQLUserModel getUserByUsername(String email) {
        return getUserByEmail(email);
    }
    
    /**
     * Gets user by ID (UUID)
     */
    public PostgreSQLUserModel getUserById(String id) {
        String sql = "SELECT " + idField + ", " + emailField + ", " + 
                     firstNameField + ", " + lastNameField + 
                     " FROM " + usersTableName + 
                     " WHERE " + idField + " = ?::uuid";
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapUser(rs);
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching user by ID", e);
        }
        
        return null;
    }
    
    /**
     * Gets user by email
     */
    public PostgreSQLUserModel getUserByEmail(String email) {
        String sql = "SELECT " + idField + ", " + emailField + ", " + 
                     firstNameField + ", " + lastNameField + 
                     " FROM " + usersTableName + 
                     " WHERE " + emailField + " = ?";
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapUser(rs);
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching user by email", e);
        }
        
        return null;
    }
    
    /**
     * Search users by attribute pattern
     */
    public List<PostgreSQLUserModel> searchForUserByUserAttribute(String attributeName, String search, int maxResults) {
        List<PostgreSQLUserModel> users = new ArrayList<>();
        String column;
        
        // Map attribute name to column name
        switch(attributeName) {
            case "username":
                column = emailField; // Since email is username
                break;
            case "email":
                column = emailField;
                break;
            case "firstName":
                column = firstNameField;
                break;
            case "lastName":
                column = lastNameField;
                break;
            default:
                return users; // Return empty list for unsupported attributes
        }
        
        String sql = "SELECT " + idField + ", " + emailField + ", " + 
                     firstNameField + ", " + lastNameField + 
                     " FROM " + usersTableName + 
                     " WHERE " + column + " LIKE ?" +
                     " LIMIT " + maxResults;
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, "%" + search + "%");
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next() && users.size() < maxResults) {
                    users.add(mapUser(rs));
                }
            }
        } catch (SQLException e) {
            logger.error("Error searching for users", e);
        }
        
        return users;
    }
    
    /**
     * Gets all users up to maxResults
     */
    public List<PostgreSQLUserModel> getAllUsers(int firstResult, int maxResults) {
        List<PostgreSQLUserModel> users = new ArrayList<>();
        
        String sql = "SELECT " + idField + ", " + emailField + ", " + 
                     firstNameField + ", " + lastNameField + 
                     " FROM " + usersTableName + 
                     " LIMIT ? OFFSET ?";
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, maxResults);
            ps.setInt(2, firstResult);
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    users.add(mapUser(rs));
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching all users", e);
        }
        
        return users;
    }
    
    /**
     * Gets user count
     */
    public int getUsersCount() {
        String sql = "SELECT COUNT(*) FROM " + usersTableName;
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.error("Error counting users", e);
        }
        
        return 0;
    }
    
    /**
     * Maps a result set to a PostgreSQLUserModel
     */
    private PostgreSQLUserModel mapUser(ResultSet rs) throws SQLException {
        String id = rs.getString(idField);
        String email = rs.getString(emailField);
        String firstName = rs.getString(firstNameField);
        String lastName = rs.getString(lastNameField);
        
        return new PostgreSQLUserModel(id, email, firstName, lastName);
    }
}