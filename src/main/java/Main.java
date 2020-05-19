

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;


public class Main {

    static String  SECRET_KEY = "Burak";

    public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        String JWT_TOKEN = generateJWT();

        boolean isValid = validateJWT(JWT_TOKEN);

        System.out.println("Is valid ? " + isValid);

        System.out.println(createJWT("01","burak tuncel test", "test2", 1000000));
    }


    public static String doHMACSHA256(String part1AndPart2, String secretKey) throws InvalidKeyException, NoSuchAlgorithmException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secretKey.getBytes(), "HmacSHA256"));

        byte[] hashBytes = mac.doFinal(part1AndPart2.getBytes());
        String hash = doBASE64(hashBytes);
        return hash;
    }

    public static String doBASE64(byte[] bytes) {
        Base64.Encoder encoder = Base64.getEncoder();
        String base64 = encoder.encodeToString(bytes);
        return base64;
    }

    public static String doBASE64(String input) {
        byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
        String base64 = doBASE64(bytes);
        return base64;
    }

    private static String generateJWT() throws IOException, NoSuchAlgorithmException, InvalidKeyException {

        String HEADER = String.join("\n", Files.readAllLines(Paths.get("C:\\Users\\ownpe\\IdeaProjects\\java-jwt\\src\\main\\resources\\header.json")));
        String PAYLOAD = String.join("\n", Files.readAllLines(Paths.get("C:\\Users\\ownpe\\IdeaProjects\\java-jwt\\src\\main\\resources\\payload.json")));

        String PART1 = doBASE64(HEADER);
        String PART2 = doBASE64(PAYLOAD);

        String PART1_PART2 = PART1 + "." + PART2;

        String PART3 = doBASE64(doHMACSHA256(PART1_PART2, SECRET_KEY));

        String JWT_TOKEN = PART1_PART2 + "." + PART3;

        return JWT_TOKEN;
    }

    public static boolean validateJWT(String jwt) throws NoSuchAlgorithmException, InvalidKeyException {

        String[] parts = jwt.split("\\.");
        String PART1 = parts[0];
        String PART2 = parts[1];
        String PART3 = parts[2];

        String PART1_PART2 = PART1 + "." + PART2;

        String jwtSignature = doBASE64(doHMACSHA256(PART1_PART2, SECRET_KEY));

        return jwtSignature.equals(PART3);

    }

    public static String createJWT(String id, String issuer, String subject, long ttlMillis) {

        //The JWT signature algorithm we will be using to sign the token
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        //if it has been specified, let's add the expiration
        if (ttlMillis > 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        //Builds the JWT and serializes it to a compact, URL-safe string
        return builder.compact();
    }



}
