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

    public PostgreSQLConnectionManager(String jdbcUrl, String username, String password, String usersTableName) {
        this.jdbcUrl = jdbcUrl;
        this.connectionProps = new Properties();
        this.connectionProps.put("user", username);
        this.connectionProps.put("password", password);

        this.usersTableName = usersTableName;
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
     * Gets the hashed password for a user by email
     *
     * @param email The email to look up
     * @return The stored password hash or null if not found
     */
    public String getPasswordHash(String email) {
        String sql = "SELECT " + PostgreSQLUserModel.FIELD_PASSWORD_DIGEST +
                     " FROM " + usersTableName +
                     " WHERE " + PostgreSQLUserModel.FIELD_EMAIL + " = ?";

        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
        } catch (SQLException e) {
            logger.error("Error retrieving password hash", e);
        }

        return null;
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
        String sql = "SELECT * FROM " + usersTableName +
                     " WHERE " + PostgreSQLUserModel.FIELD_ID + " = ?::uuid";

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
        String sql = "SELECT * FROM " + usersTableName +
                     " WHERE " + PostgreSQLUserModel.FIELD_EMAIL + " = ?";

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
                column = PostgreSQLUserModel.FIELD_EMAIL; // Since email is username
                break;
            case "email":
                column = PostgreSQLUserModel.FIELD_EMAIL;
                break;
            case "firstName":
                column = PostgreSQLUserModel.FIELD_FIRST_NAME;
                break;
            case "lastName":
                column = PostgreSQLUserModel.FIELD_LAST_NAME;
                break;
            default:
                return users; // Return empty list for unsupported attributes
        }

        String sql = "SELECT * FROM " + usersTableName +
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

        String sql = "SELECT * FROM " + usersTableName +
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
        ResultSetMetaData metaData = rs.getMetaData();
        int columnCount = metaData.getColumnCount();

        PostgreSQLUserModel user = new PostgreSQLUserModel();

        for (int i = 1; i <= columnCount; i++) {
            String columnName = metaData.getColumnName(i).toLowerCase();
            String value = rs.getString(i);

            if (value != null) {
                user.setAttribute(columnName, value);
            }
        }

        return user;
    }
}