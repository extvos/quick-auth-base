package plus.extvos.auth.utils;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.shiro.crypto.hash.SimpleHash;
import plus.extvos.common.Assert;

/**
 * @author Mingcai SHEN
 */
public class CredentialHash {
    /**
     * 密码加密算法
     */
    public static final String DEFAULT_ALGORITHM = "SHA-1";

    /**
     * 密码加密次数
     */
    public static final int DEFAULT_ITERATIONS = 2;

    public static class Hasher {
        private String algorithm = DEFAULT_ALGORITHM;
        private String salt;
        private String password;
        private int iterations;

        private Hasher() {
            iterations = 0;
        }

        public Hasher iterations(int i) {
            this.iterations = i;
            return this;
        }

        public Hasher algorithm(String alg) {
            this.algorithm = alg;
            return this;
        }

        public Hasher salt(String salt) {
            this.salt = salt;
            return this;
        }

        public Hasher password(String password) {
            this.password = password;
            return this;
        }

        public String encrypt() throws Exception {
            Assert.notEmpty(algorithm);
            Assert.notEmpty(password);
            System.out.println("encrypt:> " + algorithm + "," + iterations + "," + salt + "," + password);
            if (algorithm == null || algorithm.isEmpty()) {
                algorithm = DEFAULT_ALGORITHM;
            }
            SimpleHash simpleHash;
            if (salt != null && !salt.isEmpty()) {
                simpleHash = new SimpleHash(algorithm, password, salt);
                if (iterations > 0) {
                    simpleHash = new SimpleHash(algorithm, password, salt, iterations);
                } else {
                    simpleHash = new SimpleHash(algorithm, password, salt);
                }
            } else {
                if (iterations > 0) {
                    simpleHash = new SimpleHash(algorithm, password, iterations);
                } else {
                    simpleHash = new SimpleHash(algorithm, password);
                }
            }
            return simpleHash.toString();
        }
    }

    public static Hasher algorithm(String alg) {
        Hasher ch = new Hasher();
        ch.algorithm = alg;
        return ch;
    }

    public static Hasher salt(String salt) {
        Hasher ch = new Hasher();
        ch.salt = salt;
        return ch;
    }

    public static Hasher password(String password) {
        Hasher ch = new Hasher();
        ch.password = password;
        return ch;
    }

    public static Hasher iterations(int i) {
        Hasher ch = new Hasher();
        ch.iterations = i;
        return ch;
    }


    /**
     * 生成盐值<br/>
     *
     * @return
     */
    public static String generateSalt(int length) {
        return RandomStringUtils.randomAlphabetic(length);
    }


    public static void main(String[] args) {
        String password = "12345678";
        String salt = generateSalt(4);
        try {
            System.out.println("> " + salt + "," + CredentialHash.salt(salt).password(password).encrypt());
            System.out.println("> " + salt + "," + CredentialHash.algorithm("MD5").salt(salt).password(password).encrypt());
            System.out.println("> " + salt + "," + CredentialHash.algorithm("MD5").salt(salt).iterations(4).password(password).encrypt());
            System.out.println("> " + salt + "," + CredentialHash.algorithm("SHA-256").salt(salt).password(password).encrypt());
            System.out.println("> " + salt + "," + CredentialHash.algorithm("SHA-256").salt(salt).iterations(4).password(password).encrypt());
            System.out.println("> " + salt + "," + CredentialHash.algorithm("SHA-512").salt(salt).password(password).encrypt());
            System.out.println("> " + salt + "," + CredentialHash.algorithm("SHA-512").salt(salt).iterations(4).password(password).encrypt());
            System.out.println("> " + CredentialHash.algorithm("MD5").password(password).encrypt());
            System.out.println("2 > " + new SimpleHash("SHA-256", password, salt, 2));
            System.out.println("3 > " + new SimpleHash("SHA-256", password, salt, 4));
            System.out.println("4 > " + new SimpleHash("SHA-256", password, salt, 8));
            System.out.println("> " + CredentialHash.algorithm("MD5").salt("1234").password("12345678").encrypt());
            System.out.println("> " + CredentialHash.algorithm("SHA1").salt("1234").password("12345678").encrypt());
            String s1 = CredentialHash.algorithm("SHA1").password(password).encrypt();
            String s2 = CredentialHash.algorithm("SHA1").salt(salt).password(password).encrypt();

            String t1 = CredentialHash.algorithm("SHA1").salt(salt).password(s1).encrypt();
            String t2 = CredentialHash.algorithm("SHA1").password(s2).encrypt();

            System.out.println("> s1: " + s1);
            System.out.println("> s2: " + s2);
            System.out.println("> t1: " + t1);
            System.out.println("> t2: " + t2);

        } catch (Exception e) {
            System.out.println("ERROR:>> " + e);
        }


    }
}
