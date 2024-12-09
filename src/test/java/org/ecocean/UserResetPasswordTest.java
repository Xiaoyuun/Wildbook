package org.ecocean;

import org.apache.commons.lang3.StringEscapeUtils;
import org.ecocean.servlet.ServletUtilities;
import org.ecocean.servlet.UserResetPassword;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import static org.junit.jupiter.api.Assertions.*;

public class UserResetPasswordTest {
    /*
     * @Mock
     * HttpServletRequest request;
     * 
     * @Mock
     * HttpServletResponse response;
     * 
     */
    /*
     * @Test
     * public void testPasswordResetRequestWithPlusInUsername() throws Exception {
     * // Mock the HttpServletRequest
     * when(request.getParameter("username")).thenReturn("user+test@example.com");
     * when(request.getParameter("password")).thenReturn("newpassword123");
     * when(request.getParameter("password2")).thenReturn("newpassword123");
     * when(request.getParameter("OTP")).thenReturn("correct-otp");
     * when(request.getParameter("time")).thenReturn("1234567890");
     * 
     * // Mock the HttpServletResponse
     * PrintWriter writer = mock(PrintWriter.class);
     * when(response.getWriter()).thenReturn(writer);
     * 
     * // Simulate database behavior using Shepherd or mocking it
     * Shepherd myShepherd = mock(Shepherd.class);
     * User myUser = mock(User.class);
     * when(myShepherd.getUser("user+test@example.com")).thenReturn(myUser);
     * when(myUser.getPassword()).thenReturn("oldpassword");
     * when(myUser.getSalt()).thenReturn("salt123");
     * 
     * // Setup the expected OTP generation logic to match the expected value
     * String expectedOtp = "correct-otp"; // Replace this with your OTP generation
     * logic
     * when(myUser.getPassword()).thenReturn("hashedpassword");
     * when(myUser.getSalt()).thenReturn("salt123");
     * 
     * // Create an instance of UserResetPassword servlet
     * UserResetPassword servlet = new UserResetPassword();
     * 
     * // Call the doPost method to simulate a request
     * servlet.doPost(request, response);
     * 
     * // Verify that the response contains the expected success message
     * verify(writer).
     * println("<strong>Success:</strong> Password successfully reset.");
     * 
     * // Verify that the OTP was validated properly and that the password was
     * updated
     * // in the mock user
     * verify(myUser).setPassword("newpassword123");
     * 
     * // You can also verify that your shepherd.commitDBTransaction() or
     * // rollbackDBTransaction() was called as expected.
     * verify(myShepherd).commitDBTransaction();
     * }
     */

    @Test
    public void testUsernameFromEmailWithPlusSign() {
        String email = "user+test@example.com";
        String expectedUsername = "user-test@example.com"; // expected result after replacing the "+"
        String uuid = Util.generateUUID();

        User newUser = new User(email, uuid); // assuming the username is derived from the email

        System.out.println("username: " + newUser.getUsername());
        assertEquals(expectedUsername, newUser.getUsername());
    }

    @Test
    public void testUsernameNullWhenEmailIsEmpty() {
        String email = "";
        String uuid = "";

        User newUser = new User(email, uuid); // assuming the username is derived from the email

        assertNull(newUser.getUsername());
    }

    @Test
    public void testUserCreationAndPasswordReset() {
        // setup Shepherd and mocked parameters
        // mock Shepherd
        Shepherd myShepherd = mock(Shepherd.class);

        // setup mock behavior
        when(myShepherd.getUserByUUID(anyString())).thenReturn(null); // mock method

        // initialize with mock context and action
        String context = "context0";
        myShepherd = new Shepherd(context); // initialize with context string

        String testEmail = "testuser@example.com";
        String testUUID = "12345-abcde-67890";
        String testPassword = "securePassword123";
        String testSalt = ServletUtilities.getSalt().toHex();
        String testHashedPassword = ServletUtilities.hashAndSaltPassword(testPassword, testSalt);

        // create mock HttpServletRequest using Mockito
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock request parameters for user creation
        when(request.getParameter("uuid")).thenReturn(testUUID);
        when(request.getParameter("emailAddress")).thenReturn(testEmail);
        when(request.getParameter("password")).thenReturn(testPassword);
        when(request.getParameter("password2")).thenReturn(testPassword);

        // begin db transaction
        myShepherd.beginDBTransaction();

        // create user using email as username
        User newUser = new User(testEmail);
        newUser.setSalt(testSalt);
        newUser.setPassword(testHashedPassword);

        myShepherd.getPM().makePersistent(newUser);

        myShepherd.commitDBTransaction();

        // verify that the user was created with the correct email to username
        User retrievedUser = myShepherd.getUser(testEmail);
        assertNotNull(retrievedUser);
        assertEquals(testEmail, retrievedUser.getUsername());
        assertEquals(testHashedPassword, retrievedUser.getPassword());

        String testOTP = ServletUtilities.hashAndSaltPassword(
                testHashedPassword + "timestamp" + testSalt,
                testSalt);

        // mock request parameters for password reset
        when(request.getParameter("username")).thenReturn(testEmail);
        when(request.getParameter("password")).thenReturn("newSecurePassword456");
        when(request.getParameter("password2")).thenReturn("newSecurePassword456");
        when(request.getParameter("OTP")).thenReturn(testOTP);
        when(request.getParameter("time")).thenReturn("timestamp");

        myShepherd.beginDBTransaction();
        User userForReset = myShepherd.getUser(testEmail);

        String matchingOtpString = userForReset.getPassword() + request.getParameter("time") + userForReset.getSalt();
        matchingOtpString = ServletUtilities.hashAndSaltPassword(matchingOtpString, userForReset.getSalt());
        assertEquals(testOTP, matchingOtpString);

        // update password
        String newSalt = ServletUtilities.getSalt().toHex();
        String newHashedPassword = ServletUtilities.hashAndSaltPassword("newSecurePassword456", newSalt);
        userForReset.setPassword(newHashedPassword);
        userForReset.setSalt(newSalt);

        myShepherd.commitDBTransaction();

        // verify password
        User updatedUser = myShepherd.getUser(testEmail);
        assertEquals(newHashedPassword, updatedUser.getPassword());
    }
}