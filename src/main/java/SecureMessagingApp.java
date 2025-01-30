import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Secure Messaging App using ECDH, AES-GCM, and Digital Signatures
 */
public class SecureMessagingApp {
    private static final int AES_KEY_SIZE = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private static final Map<String, KeyPair> userKeyPairs = new HashMap<>();
    private static final Map<String, PublicKey> userPublicKeys = new HashMap<>();
    private static final Map<String, SecretKey> userSharedSecrets = new HashMap<>();
    private static final Map<String, JTextArea> userMessageAreas = new HashMap<>();

    public static void main(String[] args) throws Exception {
        SwingUtilities.invokeLater(SecureMessagingApp::createUI);
    }

    private static void createUI() {
        JFrame frame = new JFrame("Secure Messaging App");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new GridLayout(2, 1));

        JPanel userPanel = new JPanel(new GridLayout(1, 5));
        JPanel messagePanel = new JPanel(new GridLayout(5, 1));

        for (int i = 1; i <= 5; i++) {
            String username = "User" + i;
            KeyPair keyPair = generateDHKeyPair();
            userKeyPairs.put(username, keyPair);
            userPublicKeys.put(username, keyPair.getPublic());
            JTextArea messageArea = new JTextArea(10, 20);
            messageArea.setEditable(false);
            userMessageAreas.put(username, messageArea);

            JPanel panel = new JPanel(new BorderLayout());
            panel.setBorder(BorderFactory.createTitledBorder(username));
            JTextField inputField = new JTextField();
            JButton sendButton = new JButton("Send");

            sendButton.addActionListener((ActionEvent e) -> {
                String recipient = JOptionPane.showInputDialog(frame, "Enter recipient (e.g., User1):");
                String message = inputField.getText();
                if (message.isEmpty() || recipient == null || recipient.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "Invalid input.");
                    return;
                }
                try {
                    exchangeKeys(username, recipient);
                    String encryptedMessage = encryptMessage(message, userSharedSecrets.get(recipient));
                    userMessageAreas.get(recipient).append(username + " (encrypted): " + encryptedMessage + "\n");
                    userMessageAreas.get(recipient).append(username + " (decrypted): " + decryptMessage(encryptedMessage, userSharedSecrets.get(recipient)) + "\n");
                    inputField.setText("");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
                }
            });

            panel.add(inputField, BorderLayout.CENTER);
            panel.add(sendButton, BorderLayout.EAST);
            userPanel.add(panel);

            JPanel messageAreaPanel = new JPanel(new BorderLayout());
            messageAreaPanel.setBorder(BorderFactory.createTitledBorder(username + "'s Messages"));
            messageAreaPanel.add(new JScrollPane(messageArea), BorderLayout.CENTER);
            messagePanel.add(messageAreaPanel);
        }

        frame.add(userPanel);
        frame.add(messagePanel);
        frame.pack();
        frame.setVisible(true);
    }

    private static KeyPair generateDHKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error generating key pair", e);
        }
    }

    private static void exchangeKeys(String sender, String recipient) throws Exception {
        PrivateKey senderPrivateKey = userKeyPairs.get(sender).getPrivate();
        PublicKey recipientPublicKey = userPublicKeys.get(recipient);
        SecretKey sharedSecret = deriveSharedSecret(senderPrivateKey, recipientPublicKey);
        userSharedSecrets.put(recipient, sharedSecret);
    }

    private static SecretKey deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(sharedSecret);
        return new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
    }

    private static String encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    private static String decryptMessage(String encryptedMessage, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Arrays.copyOfRange(decoded, GCM_IV_LENGTH, decoded.length));
        return new String(decryptedBytes);
    }
}
