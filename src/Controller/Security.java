package Controller;

import Model.User;
import Controller.Hashing;

public class Security {
    
    private SQLite sqlite = new SQLite();
    
    public Security() {}

    // Username validation - alphanumeric, underscores, and hyphens allowed
    public boolean checkUsername(String username) {
        if (username.length() > 10) {
            return false; // Username cannot exceed 10 characters
        }
        
        // Check if username contains invalid characters
        if (!username.matches("[A-Za-z0-9_-]+")) {
            return false; // Invalid username characters
        }
        
        return true;
    }

    // Check the length of the password
    private boolean checkPasswordLength(String password) {
        return password.length() < 8;
    }

    // Check if the password contains at least one digit
    private boolean passwordHasDigit(String password) {
        return password.matches(".*\\d.*");
    }

    // Check if the password contains at least one uppercase letter
    private boolean passwordHasUppercase(String password) {
        return password.matches(".*[A-Z].*");
    }

    // Check if the password contains at least one lowercase letter
    private boolean passwordHasLowercase(String password) {
        return password.matches(".*[a-z].*");
    }

    // Check if the password contains at least one special character
    private boolean passwordHasSpecialChar(String password) {
        return password.matches(".*[`~!@#$%^&*()\\_=+\\\\|\\[{\\]}:<>.?].*");
    }

    // Password strength validation
    public boolean checkPasswordStrength(String password, javax.swing.JLabel errorLabel, javax.swing.JTextField passwordFld, javax.swing.JTextField confpassFld) {

        // Ensure password is at least 8 characters long
        if (checkPasswordLength(password)) {
            errorLabel.setText("Error: Password must be at least 8 characters long.");
            return false;
        }

        // Ensure password contains at least one uppercase letter
        if (!passwordHasUppercase(password)) {
            errorLabel.setText("Error: Password must contain at least 1 uppercase letter.");
            return false;
        }

        // Ensure password contains at least one lowercase letter
        if (!passwordHasLowercase(password)) {
            errorLabel.setText("Error: Password must contain at least 1 lowercase letter.");
            return false;
        }

        // Ensure password contains at least one digit
        if (!passwordHasDigit(password)) {
            errorLabel.setText("Error: Password must contain at least 1 digit.");
            return false;
        }

        // Ensure password contains at least one special character
        if (!passwordHasSpecialChar(password)) {
            errorLabel.setText("Error: Password must contain at least 1 special character.");
            return false;
        }

        // If all checks are passed, clear the error label
        errorLabel.setText("");
        return true;
    }

    // Check if a user already exists in the database
    public boolean checkUser(String username) {
        try {
            User user = sqlite.getUser(username);
            return user.getId() != 0; // User exists
        } catch (NullPointerException e) {
            return false; // User does not exist
        }
    }

    // Verify user password (checks if the provided password matches the stored one)
    public boolean verifyUser(String username, String password) {
        try {
            User user = sqlite.getUser(username);
            if (user.getId() == 0) {
                return false; // User does not exist
            }
            // Verify if the provided password matches the stored password
            return Hashing.verifyUserPassword(password, user.getPassword());
        } catch (NullPointerException e) {
            return false; // User does not exist
        }
    }

    // Check if the user is locked
    public boolean isUserLocked(String username) {
        try {
            User user = sqlite.getUser(username);
            if (user.getId() == 0) {
                return false; // User does not exist
            }
            return user.getLocked() != 0; // Check if the user is locked
        } catch (NullPointerException e) {
            return false; // User does not exist
        }
    }

    // Lock the user (disable the account)
    public void lockUser(String username) {
        try {
            User user = sqlite.getUser(username);
            if (user.getId() != 0) {
                user.setLocked(1); // Lock the user account
                sqlite.updateUser(user); // Update the user's locked status
            }
        } catch (NullPointerException e) {
            return; // User does not exist
        }
    }
}
