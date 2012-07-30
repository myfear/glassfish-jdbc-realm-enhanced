package net.eisele.security.util;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * A set of test-cases to veryfy that the {@link SecurityStore} is working.
 *
 * @author eiselem
 */
public class SecurityStoreTest {

    /**
     * get username and password from the surefire system properties.
     */
    private final static String USER = System.getProperty("user");
    private final static String PASSWORD = System.getProperty("password");

    @org.junit.BeforeClass
    public static void setupUsers() {
        System.out.println("addUser testUser1");
        String name = "testUser1";
        String salt = "salt1";
        String password = "password1";
        SecurityStore instance = new SecurityStore(USER, PASSWORD);
        instance.addUser(name, salt, password);

        System.out.println("addUser testUser1");
        String name2 = "testUser2";
        String salt2 = "salt2";
        String password2 = "password2";

        instance.addUser(name2, salt2, password2);

    }

    /**
     * Test of getSaltForUser method, of class SecurityStore.
     */
    @Test
    public void getSaltForUser() {
        System.out.println("getSaltForUser");
        String name = "testUser1";
        SecurityStore instance = new SecurityStore(USER, PASSWORD);
        String expResult = "salt1";
        String result = instance.getSaltForUser(name);
        assertEquals(expResult, result);
    }

    /**
     * Test of validateUser method, of class SecurityStore.
     */
    @Test
    public void validateUser() {
        System.out.println("validateUser");
        String name = "testUser1";
        String password = "password1";
        SecurityStore instance = new SecurityStore(USER, PASSWORD);
        boolean expResult = true;
        boolean result = instance.validateUser(name, password);
        assertEquals(expResult, result);
    }

    /**
     * Test of validateUser method, of class SecurityStore.
     */
    @Test
    public void validateFalseUser() {
        System.out.println("validateFalseUser");
        String name = "testUser1";
        String password = "password2";
        SecurityStore instance = new SecurityStore(USER, PASSWORD);
        boolean expResult = false;
        boolean result = instance.validateUser(name, password);
        assertEquals(expResult, result);
    }
}
