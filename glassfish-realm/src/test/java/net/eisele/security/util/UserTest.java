package net.eisele.security.util;

import java.util.logging.Level;
import java.util.logging.Logger;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * A set of test-cases to verify that the
 *
 * @author eiselem
 */
public class UserTest {

    /**
     * get username and password from the surefire system properties.
     */
    private final static String USER = System.getProperty("user");
    private final static String PASSWORD = System.getProperty("password");
    public static final Logger LOGGER = Logger.getLogger(UserTest.class.getName());

    /**
     * Add the test-users
     */
    @org.junit.BeforeClass
    public static void addUsers() {
        String user1 = "user1";
        String user2 = "user2";
        String passwordStr = "TestPassword";
        Password pwd = new Password();

        byte[] saltBytes = pwd.getSalt(64);
        byte[] passwordBytes = pwd.hashWithSalt(passwordStr, saltBytes);

        String password = pwd.base64FromBytes(passwordBytes);
        String salt = pwd.base64FromBytes(saltBytes);

        SecurityStore store = new SecurityStore(USER, PASSWORD);
        store.addUser(user1, salt, password);
        store.addUser(user2, salt, password);

        LOGGER.log(Level.INFO, "Bytes {0}", passwordBytes);
        LOGGER.log(Level.INFO, "String {0}", password);

    }

    /**
     * Validate user 1
     */
    @Test
    public void validateUser1() {
        String user = "user1";
        String passwordStr = "TestPassword";
        SecurityStore store = new SecurityStore(USER, PASSWORD);
        String salt = store.getSaltForUser(user);
        Password pwd = new Password();

        // get the byte[] from the salt
        byte[] saltBytes = pwd.bytesFrombase64(salt);
        // hash password and salt
        byte[] passwordBytes = pwd.hashWithSalt(passwordStr, saltBytes);
        // Base64 encode to String
        String password = pwd.base64FromBytes(passwordBytes);
        LOGGER.log(Level.INFO, "PWD Generated {0}", password);
        // validate password with the db
        boolean validated = store.validateUser(user, password);
        assertTrue(validated);

    }

    /**
     * Validate Fail Login User 2
     */
    @Test
    public void validateFailUser2() {
        String user = "user2";
        String passwordStr = "TestPassword2";


        SecurityStore store = new SecurityStore(USER, PASSWORD);
        String salt = store.getSaltForUser(user);

        Password pwd = new Password();

        // get the byte[] from the salt
        byte[] saltBytes = pwd.bytesFrombase64(salt);
        // hash password and salt
        byte[] passwordBytes = pwd.hashWithSalt(passwordStr, saltBytes);
        // Base64 encode to String
        String password = pwd.base64FromBytes(passwordBytes);
        LOGGER.log(Level.INFO, "PWD Generated {0}", password);
        // validate password with the db
        boolean validated = store.validateUser(user, password);
        assertFalse(validated);

    }
}
