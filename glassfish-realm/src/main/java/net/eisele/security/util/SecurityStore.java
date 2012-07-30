package net.eisele.security.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

/**
 * Database abstraction for a User and a Group table to use with a GlassFish
 * realm.
 *
 * @author eiselem
 */
public class SecurityStore {

    private Connection con;
    private final static Logger LOGGER = Logger.getLogger(Password.class.getName());
    private final static String ADD_USER = "INSERT INTO users VALUES(?,?,?);";
    private final static String SALT_FOR_USER = "SELECT salt FROM users u WHERE username = ?;";
    private final static String VERIFY_USER = "SELECT username FROM users u WHERE username = ? AND password = ?;";

    /**
     * Public constructor for use with Java EE App-servers or Clients which have
     * access to an InitialContext. In this case a javax.sql.DataSource is
     * looked up with the Context.
     *
     * @param dataSource
     */
    public SecurityStore(String dataSource) {
        Context ctx = null;
        try {
            ctx = new InitialContext();
            DataSource ds = (javax.sql.DataSource) ctx.lookup(dataSource);
            con = ds.getConnection();
        } catch (NamingException | SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting connection!", e);
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException e) {
                    LOGGER.log(Level.SEVERE, "Error closing context!", e);
                }
            }
        }
    }

    /**
     * Public constructor for use with standalone tests or separate databases.
     * User and password have to be supplied. MySQL Database is assumed to be on
     * localhost:3306 and schema called "jdbcrealmdb"
     *
     * @param user
     * @param passwd
     */
    public SecurityStore(String user, String passwd) {
        try {
            Class.forName("com.mysql.jdbc.Driver").newInstance();

            con = DriverManager
                    .getConnection("jdbc:mysql://localhost:3306/jdbcrealmdb?user=" + user + "&password=" + passwd + "");
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | SQLException ex) {
            Logger.getLogger(SecurityStore.class.getName()).log(Level.SEVERE, "Error getting connection", ex);
        }
    }

    /**
     * Adds a User to the Database
     *
     * @param name The username
     * @param salt The dynamic salt
     * @param password The password (Hashed)
     */
    public void addUser(String name, String salt, String password) {
        try {
            PreparedStatement pstm = con.prepareStatement(ADD_USER);
            pstm.setString(1, name);
            pstm.setString(2, salt);
            pstm.setString(3, password);
            pstm.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.log(Level.SEVERE, "Create User failed!", ex);
        }
    }

    /**
     * Get's the salt for a given user
     *
     * @param name User name
     * @return
     */
    public String getSaltForUser(String name) {
        String salt = null;
        try {
            PreparedStatement pstm = con.prepareStatement(SALT_FOR_USER);
            pstm.setString(1, name);
            ResultSet rs = pstm.executeQuery();

            if (rs.next()) {
                salt = rs.getString(1);
            }

        } catch (SQLException ex) {
            LOGGER.log(Level.SEVERE, "User not found!", ex);
        }
        return salt;
    }

    /**
     * validates a user with a given password and a username
     *
     * @param name the username
     * @param password the password (Hashed)
     * @return
     */
    public boolean validateUser(String name, String password) {

        try {
            PreparedStatement pstm = con.prepareStatement(VERIFY_USER);
            pstm.setString(1, name);
            pstm.setString(2, password);
            ResultSet rs = pstm.executeQuery();
            if (rs.next()) {
                return true;
            }
        } catch (SQLException ex) {
            LOGGER.log(Level.SEVERE, "User validation failed!", ex);
        }
        return false;
    }
}
