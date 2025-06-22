// PIHASH.java
import javax.swing.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.awt.*;
import java.util.Base64;
import java.util.List;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PIHASH {
    private static final String USERS_FILE = "users.txt";
    private static final String VAULT_DIR = "vaults/";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(LoginFrame::new);
    }

    static String encrypt(String plainText, String keyStr) {
        try {
            SecretKeySpec key = getKey(keyStr);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }

    static String decrypt(String encryptedText, String keyStr) {
        try {
            SecretKeySpec key = getKey(keyStr);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decrypted);
        } catch (Exception e) {
            return null;
        }
    }

    private static SecretKeySpec getKey(String keyStr) {
        byte[] key = new byte[16];
        byte[] input = keyStr.getBytes();
        System.arraycopy(input, 0, key, 0, Math.min(input.length, 16));
        return new SecretKeySpec(key, "AES");
    }

    static class LoginFrame extends JFrame {
        JTextField emailField;
        JPasswordField passwordField;

        public LoginFrame() {
            setTitle("PIHASH - Login");
            setSize(800, 500);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            setContentPane(new JPanel() {
                private final Image background = new ImageIcon("sign.png").getImage();
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    g.setColor(Color.BLACK);
                    g.fillRect(0, 0, getWidth(), getHeight());
                    g.drawImage(background, 0, 0, getWidth(), getHeight(), this);
                }
            });
            setLayout(null);

            JLabel emailLabel = new JLabel("Email:");
            emailLabel.setBounds(300, 130, 100, 25);
            emailLabel.setForeground(Color.YELLOW);
            emailLabel.setFont(new Font("Arial", Font.BOLD, 16));
            add(emailLabel);

            emailField = new JTextField();
            emailField.setBounds(400, 130, 200, 25);
            add(emailField);

            JLabel passwordLabel = new JLabel("Master Password:");
            passwordLabel.setBounds(250, 180, 150, 25);
            passwordLabel.setForeground(Color.YELLOW);
            passwordLabel.setFont(new Font("Arial", Font.BOLD, 16));
            add(passwordLabel);

            passwordField = new JPasswordField();
            passwordField.setBounds(400, 180, 200, 25);
            add(passwordField);

            JButton loginButton = new JButton("Login");
            loginButton.setBounds(400, 230, 100, 30);
            loginButton.addActionListener(e -> login());
            add(loginButton);

            JButton signupRedirect = new JButton("Signup");
            signupRedirect.setBounds(510, 230, 100, 30);
            signupRedirect.addActionListener(e -> {
                dispose();
                new SignupFrame();
            });
            add(signupRedirect);

            setVisible(true);
        }

        void login() {
            String email = emailField.getText().trim();
            String password = new String(passwordField.getPassword()).trim();
            if (email.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please fill in all fields.");
                return;
            }

            try (BufferedReader br = new BufferedReader(new FileReader(USERS_FILE))) {
                String line;
                while ((line = br.readLine()) != null) {
                    String[] parts = line.split(",");
                    if (parts.length >= 3 && parts[0].equalsIgnoreCase(email)) {
                        String decrypted = decrypt(parts[2], password);
                        if (decrypted != null && decrypted.equals(password)) {
                            JOptionPane.showMessageDialog(this, "Login successful!");
                            dispose();
                            new VaultFrame(parts[1], password);
                            return;
                        }
                    }
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }

            JOptionPane.showMessageDialog(this, "Invalid credentials.");
        }
    }

    static class SignupFrame extends JFrame {
        JTextField firstName, lastName, country, address, email, username;
        JPasswordField passwordField;

        public SignupFrame() {
            setTitle("PIHASH - Signup");
            setSize(800, 600);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            setContentPane(new JPanel() {
                private final Image background = new ImageIcon("sign.png").getImage();
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    g.setColor(Color.BLACK);
                    g.fillRect(0, 0, getWidth(), getHeight());
                    g.drawImage(background, 0, 0, getWidth(), getHeight(), this);
                }
            });
            setLayout(null);

            addLabel("First Name:", 100, 50); firstName = addTextField(250, 50);
            addLabel("Last Name:", 100, 90); lastName = addTextField(250, 90);
            addLabel("Country:", 100, 130); country = addTextField(250, 130);
            addLabel("Postal Address:", 100, 170); address = addTextField(250, 170);
            addLabel("Email:", 100, 210); email = addTextField(250, 210);
            addLabel("Username:", 100, 250); username = addTextField(250, 250);

            addLabel("Master Password:", 100, 290);
            passwordField = new JPasswordField();
            passwordField.setBounds(250, 290, 200, 25);
            add(passwordField);

            JButton signupButton = new JButton("Signup");
            signupButton.setBounds(250, 340, 100, 30);
            signupButton.addActionListener(e -> signup());
            add(signupButton);

            JButton backButton = new JButton("Back");
            backButton.setBounds(360, 340, 100, 30);
            backButton.addActionListener(e -> {
                dispose();
                new LoginFrame();
            });
            add(backButton);

            setVisible(true);
        }

        void addLabel(String text, int x, int y) {
            JLabel label = new JLabel(text);
            label.setBounds(x, y, 150, 25);
            label.setForeground(Color.WHITE);
            label.setFont(new Font("Arial", Font.BOLD, 14));
            add(label);
        }

        JTextField addTextField(int x, int y) {
            JTextField tf = new JTextField();
            tf.setBounds(x, y, 200, 25);
            add(tf);
            return tf;
        }

        void signup() {
            String fn = firstName.getText().trim();
            String ln = lastName.getText().trim();
            String cn = country.getText().trim();
            String ad = address.getText().trim();
            String em = email.getText().trim();
            String un = username.getText().trim();
            String pw = new String(passwordField.getPassword()).trim();

            if (fn.isEmpty() || ln.isEmpty() || cn.isEmpty() || ad.isEmpty() || em.isEmpty() || un.isEmpty() || pw.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please fill all fields.");
                return;
            }

            try {
                File userFile = new File(USERS_FILE);
                if (!userFile.exists()) userFile.createNewFile();
                List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));
                for (String line : lines) {
                    String[] parts = line.split(",");
                    if (parts.length >= 2 && (parts[0].equalsIgnoreCase(em) || parts[1].equalsIgnoreCase(un))) {
                        JOptionPane.showMessageDialog(this, "User already exists.");
                        return;
                    }
                }
                String encryptedPassword = encrypt(pw, pw);
                Files.write(Paths.get(USERS_FILE),
                    Arrays.asList(em + "," + un + "," + encryptedPassword),
                    StandardOpenOption.APPEND);
                File vault = new File(VAULT_DIR + un + ".txt");
                vault.getParentFile().mkdirs();
                vault.createNewFile();

                JOptionPane.showMessageDialog(this, "Signup successful. You can login now.");
                dispose();
                new LoginFrame();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}