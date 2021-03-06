package cn.shine;

/*
 * @Project PHE-Maven
 * @Package cn.shine
 * @Class   App
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/4 13:17
 * @License MIT
 */

import cn.shine.phe.Paillier;
import org.jetbrains.annotations.NotNull;

import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * A Python-based phe library to implement Paillier Homomorphic Encryption method
 * <p>
 * Python Library <p>
 * |- title:     phe <p>
 * |- summary:   Partially Homomorphic Encryption library for Python <p>
 * |- uri:       <a href="https://github.com/data61/python-paillier">https://github.com/data61/python-paillier</a> <p>
 * |- version:   1.5.0 <p>
 * |- author:    CSIRO's Data61 <p>
 * |- email:     confidential-computing@data61.csiro.au <p>
 * |- license:   GPLv3 <p>
 * |- copyright: Copyright 2013-2019 CSIRO's Data61
 * <p>
 * Java Library <p>
 * |- title:     phe-java <p>
 * |- summary:   Partially Homomorphic Encryption library for Java <p>
 * |- uri:       <a href="https://github.com/shine813/PHE-Maven">https://github.com/shine813/PHE-Maven</a>
 * |- version:   1.0.0 <p>
 * |- author:    Zhan Shi <p>
 * |- email:     phe.zshi@gmail.com <p>
 * |- license:   MIT <p>
 * |- copyright: Copyright (c) 2021 Zhan Shi
 *
 * @author Zhan Shi
 */
public class App {
    /**
     * todo private static secureCompute(...): example function
     *
     * @param keyPair paillier key pair
     * @param m       plaintext
     * @param c       ciphertext
     * @param m1      plaintext 1
     * @param c1      ciphertext 1
     * @param m2      plaintext 2
     * @param c2      ciphertext 2
     * @param v       result
     * @param v2      result 2
     * @param v3      result 3
     * @param v4      result 4
     */
    private static void secureCompute(Paillier.@NotNull PaillierKeyPair keyPair, Integer m,
                                      Paillier.@NotNull EncryptedNumber c, Integer m1, Paillier.EncryptedNumber c1,
                                      Double m2, Paillier.EncryptedNumber c2,
                                      double v, double v2, double v3, double v4) {
        // Integer type example
        assert keyPair.privateKey.decrypt(c.add(c1)).equals(BigInteger.valueOf(m + m1));
        assert keyPair.privateKey.decrypt(c.subtract(c1)).equals(BigInteger.valueOf(m - m1));
        assert keyPair.privateKey.decrypt(c.multiply(m1)).equals(BigInteger.valueOf((long) m * m1));
        assert keyPair.privateKey.decrypt(c.divide(m1)).equals(BigDecimal.valueOf((m / m1) * 1.0));
        // Double or Float type example
        assert keyPair.privateKey.decrypt(c.add(c2)).equals(BigDecimal.valueOf(v));
        assert keyPair.privateKey.decrypt(c.subtract(c2)).equals(BigDecimal.valueOf(v2));
        assert keyPair.privateKey.decrypt(c.multiply(m2)).equals(BigDecimal.valueOf(v3));
        assert keyPair.privateKey.decrypt(c.divide(m2)).equals(BigDecimal.valueOf(v4));
    }

    /**
     * todo Public Static main(String[]): main function
     *
     * @param args some args
     */
    public static void main(String[] args) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(512);

        Integer m = 10;
        Paillier.EncryptedNumber c = keyPair.publicKey.encrypt(m);

        Integer m1 = 5;
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        Double m2 = 2.5;
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        Integer m3 = -5;
        Paillier.EncryptedNumber c3 = keyPair.publicKey.encrypt(m3);

        Double m4 = -2.5;
        Paillier.EncryptedNumber c4 = keyPair.publicKey.encrypt(m4);

        secureCompute(keyPair, m, c, m1, c1, m2, c2, m + m2, m - m2, m * m2, m / m2);

        secureCompute(keyPair, m, c, m3, c3, m4, c4, m + m4, m - m4, m * m4, m/ m4);
    }
}
