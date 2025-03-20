package org.keycloak.storage.postgresql;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Manages PostgreSQL database connections and queries for user federation
 */
public class PostgreSQLConnectionManager {
    private static final Logger logger = LoggerFactory.getLogger(PostgreSQLConnectionManager.class);
    
    private final String jdbcUrl;
    private final Properties connectionProps;
    
    private final String usersTableName;
    private final String usernameField;
    private final String passwordField;
    private final String emailField;
    private final String firstNameField;
    private final String lastNameField;
    
    public PostgreSQLConnectionManager(String jdbcUrl, String username, String password,
                                      String usersTableName, String usernameField, String passwordField, 
                                      String emailField, String firstNameField, String lastNameField) {
        this.jdbcUrl = jdbcUrl;
        this.connectionProps = new Properties();
        this.connectionProps.put("user", username);
        this.connectionProps.put("password", password);
        
        this.usersTableName = usersTableName;
        this.usernameField = usernameField;
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
     * Check if user exists by username
     */
    public boolean validateUser(String username, String password) {
        String sql = "SELECT " + passwordField + " FROM " + usersTableName + 
                     " WHERE " + usernameField + " = ?";
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedPassword = rs.getString(1);
                    // Direct password comparison - in a real implementation, 
                    // you should use appropriate password hashing/verification
                    return password.equals(storedPassword);
                }
            }
        } catch (SQLException e) {
            logger.error("Error validating user", e);
        }
        
        return false;
    }
    
    /**
     * Gets user by username
     */
    public PostgreSQLUserModel getUserByUsername(String username) {
        String sql = "SELECT " + usernameField + ", " + emailField + ", " + 
                     firstNameField + ", " + lastNameField + 
                     " FROM " + usersTableName + 
                     " WHERE " + usernameField + " = ?";
                     
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapUser(rs);
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching user by username", e);
        }
        
        return null;
    }
    
    /**
     * Gets user by email
     */
    public PostgreSQLUserModel getUserByEmail(String email) {
        String sql = "SELECT " + usernameField + ", " + emailField + ", " + 
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
     * Search users by username pattern
     */
    public List<PostgreSQLUserModel> searchForUserByUserAttribute(String attributeName, String search, int maxResults) {
        List<PostgreSQLUserModel> users = new ArrayList<>();
        String column;
        
        // Map attribute name to column name
        switch(attributeName) {
            case "username":
                column = usernameField;
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
        
        String sql = "SELECT " + usernameField + ", " + emailField + ", " + 
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
        
        String sql = "SELECT " + usernameField + ", " + emailField + ", " + 
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
        String username = rs.getString(usernameField);
        String email = rs.getString(emailField);
        String firstName = rs.getString(firstNameField);
        String lastName = rs.getString(lastNameField);
        
        return new PostgreSQLUserModel(username, email, firstName, lastName);
    }
}