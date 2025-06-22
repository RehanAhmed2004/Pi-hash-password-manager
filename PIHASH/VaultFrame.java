import javax.swing.*;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.BorderLayout;

public class VaultFrame extends JFrame {
    private final String username;
    private final String masterPassword;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final String vaultFilePath;
    private final Map<Integer, String> encryptedPasswords = new HashMap<>();
    private final Set<Integer> revealedRows = new HashSet<>();

    public VaultFrame(String username, String masterPassword) {
        this.username = username;
        this.masterPassword = masterPassword;
        this.vaultFilePath = "vaults/" + username + ".txt";

        setTitle("PIHASH Vault - " + username);
        setSize(1000, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        BackgroundPanel backgroundPanel = new BackgroundPanel("vault.png");
        backgroundPanel.setLayout(new BorderLayout());
        setContentPane(backgroundPanel);

        tableModel = new DefaultTableModel(new String[]{"Site", "Username", "Password"}, 0);
        table = new JTable(tableModel);
        table.setFont(new Font("Arial", Font.PLAIN, 14));
        table.setForeground(Color.BLACK);
        table.setBackground(Color.DARK_GRAY);
        table.setRowHeight(30);

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                int row = table.rowAtPoint(evt.getPoint());
                int col = table.columnAtPoint(evt.getPoint());
                if (col == 2 && row >= 0) {
                    if (revealedRows.contains(row)) {
                        tableModel.setValueAt("********", row, 2);
                        revealedRows.remove(row);
                    } else {
                        String enc = encryptedPasswords.get(row);
                        String dec = decrypt(enc, masterPassword);
                        tableModel.setValueAt(dec, row, 2);
                        revealedRows.add(row);
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        backgroundPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel controls = new JPanel(new GridLayout(2, 4, 10, 10));
        controls.setBackground(Color.BLACK);

        String[] buttonLabels = {"Add", "Delete", "Edit", "Generate Password", "Search", "Export", "Import", "Sign Out"};
        JButton[] buttons = new JButton[buttonLabels.length];

        for (int i = 0; i < buttonLabels.length; i++) {
            buttons[i] = new JButton(buttonLabels[i]);
            buttons[i].setFont(new Font("Arial", Font.BOLD, 14));
            controls.add(buttons[i]);
        }

        buttons[0].addActionListener(e -> addEntry());
        buttons[1].addActionListener(e -> deleteEntry());
        buttons[2].addActionListener(e -> editEntry());
        buttons[3].addActionListener(e -> JOptionPane.showMessageDialog(this, generatePassword()));
        buttons[4].addActionListener(e -> searchEntry());
        buttons[5].addActionListener(e -> exportVault());
        buttons[6].addActionListener(e -> importVault());
        buttons[7].addActionListener(e -> {
            dispose();
            new PIHASH.LoginFrame();
        });

        backgroundPanel.add(controls, BorderLayout.SOUTH);

        loadVault();
        setVisible(true);
        table.setOpaque(false);
        ((JComponent) table.getDefaultRenderer(Object.class)).setOpaque(false);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        add(scrollPane, BorderLayout.CENTER);
        controls.setOpaque(false);
        controls.setBackground(new Color(0, 0, 0, 150));
        setLocationRelativeTo(null);
    }

    private void loadVault() {
        try {
            tableModel.setRowCount(0);
            encryptedPasswords.clear();
            revealedRows.clear();
            java.util.List<String> lines = Files.readAllLines(Paths.get(vaultFilePath));
            for (int i = 0; i < lines.size(); i++) {
                String[] parts = lines.get(i).split(",");
                if (parts.length == 3) {
                    tableModel.addRow(new Object[]{parts[0], parts[1], "********"});
                    encryptedPasswords.put(i, parts[2]);
                }
            }
        } catch (IOException e) {
            System.out.println("Vault file not found or unreadable: " + vaultFilePath);
        }
    }

    private void saveVault() {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(vaultFilePath))) {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                String site = (String) tableModel.getValueAt(i, 0);
                String user = (String) tableModel.getValueAt(i, 1);
                String encrypted = encryptedPasswords.getOrDefault(i, encrypt((String) tableModel.getValueAt(i, 2), masterPassword));
                bw.write(site + "," + user + "," + encrypted);
                bw.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void addEntry() {
        JTextField siteField = new JTextField();
        JTextField userField = new JTextField();
        JPasswordField passField = new JPasswordField();
        JButton genButton = new JButton("Generate");
        genButton.addActionListener(e -> passField.setText(generatePassword()));

        JPanel panel = new JPanel(new GridLayout(4, 2));
        panel.add(new JLabel("Site:")); panel.add(siteField);
        panel.add(new JLabel("Username:")); panel.add(userField);
        panel.add(new JLabel("Password:")); panel.add(passField);
        panel.add(new JLabel(" ")); panel.add(genButton);

        int option = JOptionPane.showConfirmDialog(this, panel, "Add Entry", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String site = siteField.getText().trim();
            String user = userField.getText().trim();
            String pass = new String(passField.getPassword()).trim();
            if (!site.isEmpty() && !user.isEmpty() && !pass.isEmpty()) {
                String encPass = encrypt(pass, masterPassword);
                int row = tableModel.getRowCount();
                tableModel.addRow(new Object[]{site, user, "********"});
                encryptedPasswords.put(row, encPass);
                saveVault();
            } else {
                JOptionPane.showMessageDialog(this, "Invalid entry.");
            }
        }
    }

    private void deleteEntry() {
        int row = table.getSelectedRow();
        if (row >= 0) {
            tableModel.removeRow(row);
            encryptedPasswords.remove(row);
            revealedRows.remove(row);
            saveVault();
        }
    }

    private void editEntry() {
        int row = table.getSelectedRow();
        if (row >= 0) {
            JTextField siteField = new JTextField((String) tableModel.getValueAt(row, 0));
            JTextField userField = new JTextField((String) tableModel.getValueAt(row, 1));
            JPasswordField passField = new JPasswordField();

            JPanel panel = new JPanel(new GridLayout(3, 2));
            panel.add(new JLabel("Site:")); panel.add(siteField);
            panel.add(new JLabel("Username:")); panel.add(userField);
            panel.add(new JLabel("New Password (leave blank to keep current):")); panel.add(passField);

            int option = JOptionPane.showConfirmDialog(this, panel, "Edit Entry", JOptionPane.OK_CANCEL_OPTION);
            if (option == JOptionPane.OK_OPTION) {
                tableModel.setValueAt(siteField.getText().trim(), row, 0);
                tableModel.setValueAt(userField.getText().trim(), row, 1);
                String newPass = new String(passField.getPassword()).trim();
                if (!newPass.isEmpty()) {
                    String newEnc = encrypt(newPass, masterPassword);
                    encryptedPasswords.put(row, newEnc);
                    tableModel.setValueAt("********", row, 2);
                    revealedRows.remove(row);
                }
                saveVault();
            }
        }
    }

    private void searchEntry() {
        String keyword = JOptionPane.showInputDialog(this, "Enter site or username to search:");
        if (keyword == null || keyword.trim().isEmpty()) return;

        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String site = (String) tableModel.getValueAt(i, 0);
            String user = (String) tableModel.getValueAt(i, 1);
            if (site.contains(keyword) || user.contains(keyword)) {
                table.setRowSelectionInterval(i, i);
                return;
            }
        }
        JOptionPane.showMessageDialog(this, "No matching entry found.");
    }

    private void exportVault() {
        try {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                Files.copy(Paths.get(vaultFilePath), chooser.getSelectedFile().toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void importVault() {
        try {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                java.util.List<String> lines = Files.readAllLines(chooser.getSelectedFile().toPath());
                for (int i = 0; i < lines.size(); i++) {
                    String[] parts = lines.get(i).split(",");
                    if (parts.length == 3) {
                        tableModel.addRow(new Object[]{parts[0], parts[1], "********"});
                        encryptedPasswords.put(tableModel.getRowCount() - 1, parts[2]);
                    }
                }
                saveVault();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String generatePassword() {
        SecureRandom rand = new SecureRandom();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%&*!";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(chars.charAt(rand.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private static SecretKeySpec getKey(String keyStr) {
        byte[] key = new byte[16];
        byte[] inputBytes = keyStr.getBytes();
        System.arraycopy(inputBytes, 0, key, 0, Math.min(inputBytes.length, key.length));
        return new SecretKeySpec(key, "AES");
    }

    private static String encrypt(String plainText, String key) {
        try {
            SecretKeySpec secretKey = getKey(key);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            return null;
        }
    }

    private static String decrypt(String encryptedText, String key) {
        try {
            SecretKeySpec secretKey = getKey(key);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(decrypted);
        } catch (Exception e) {
            return "********";
        }
    }

    class BackgroundPanel extends JPanel {
        private final Image backgroundImage;

        public BackgroundPanel(String imagePath) {
            ImageIcon icon = new ImageIcon(imagePath);
            backgroundImage = icon.getImage();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            g.drawImage(backgroundImage, 0, 0, getWidth(), getHeight(), this);
        }
    }
}
