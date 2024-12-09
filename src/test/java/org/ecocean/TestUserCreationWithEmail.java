package org.ecocean;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class TestUserCreationWithEmail {

    @Test
    void testUserAccountCreationWithEmail() {
        // mock dependencies
        Shepherd mockShepherd = mock(Shepherd.class);

        // simulate input parameters
        String uuid = "12345";
        String email = "test+example@example.com";
        String password = "password123";

        // mock the behavior of Shepherd's methods
        when(mockShepherd.getUserByUUID(uuid)).thenReturn(null); // assume user does not already exist

        // execute the user creation logic
        User newUser = null;
        try {
            // simulate the account creation logic
            newUser = new User(uuid);
            newUser.setEmailAddress(email);
            newUser.setPassword(password); // mocked hashing/salting can be added

            // save the new user using Shepherd
            mockShepherd.getPM().makePersistent(newUser);
        } catch (Exception e) {
            fail("Exception during user creation: " + e.getMessage());
        }

        // assertions
        assertNotNull(newUser);
        assertEquals(email, newUser.getEmailAddress());
        assertEquals(uuid, newUser.getUUID());
    }
}