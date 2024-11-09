package Fo;

import java.util.HashMap;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class UserAuthSystem {

    // In-memory user store
    private static HashMap<String, String> users = new HashMap<>();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        while (true) {
            System.out.println("\n--- User Authentication System ---");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");
            int option = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (option) {
                case 1:
                    register();
                    break;
                case 2:
                    login();
                    break;
                case 3:
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }

    // Method to register a new user
    private static void register() {
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        if (users.containsKey(username)) {
            System.out.println("Username already exists. Please choose a different one.");
            return;
        }

        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        if (!isValidPassword(password)) {
            System.out.println("Password must be at least 6 characters long and contain a mix of letters and numbers.");
            return;
        }

        // Hash the password before storing it
        String hashedPassword = hashPassword(password);
        if (hashedPassword == null) {
            System.out.println("Error hashing password. Please try again.");
            return;
        }

        users.put(username, hashedPassword);
        System.out.println("User registered successfully!");
    }

    // Method to log in an existing user
    private static void login() {
        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        // Hash the entered password and compare with stored hash
        String hashedPassword = hashPassword(password);
        if (hashedPassword != null && hashedPassword.equals(users.get(username))) {
            System.out.println("Login successful!");
        } else {
            System.out.println("Invalid username or password.");
        }
    }

    // Method to validate password strength
    private static boolean isValidPassword(String password) {
        return password.length() >= 6 && Pattern.compile("[a-zA-Z]").matcher(password).find() &&
                Pattern.compile("[0-9]").matcher(password).find();
    }

    // Method to hash a password using SHA-256
    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b)); 
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}

