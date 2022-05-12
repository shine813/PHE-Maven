package io.github.shine813;

/*
 * @Project PHE-Maven
 * @Package cn.shine
 * @Class   AppTest
 * @Version 1.0.0
 * @Author  Zhan Shi
 * @Time    2022/5/7 21:51
 * @License MIT
 */

import io.github.shine813.phe.Paillier;
import io.github.shine813.report.ZTestReport;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;

import static junit.framework.TestCase.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Paillier Homomorphic Encryption Test
 *
 * @author Zhan Shi
 */
@Listeners({ZTestReport.class})
public class AppTest {
    /**
     * todo DataProvider keyLengthsProvider
     *
     * @return Object[][] -> {{int}, ...}
     */
    @DataProvider(name = "keyLength")
    public Object[][] keyLengthsProvider() {
        return new Object[][]{{128}, {256}, {512}, {1024}, {2048}, {3072}, {4096}};
    }


    /**
     * todo Test generateKeypairTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Generate Keypair Test", dataProvider = "keyLength")
    public void generateKeypairTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        assertEquals(keyPair.publicKey, keyPair.privateKey.publicKey);
    }

    /**
     * todo Test addIntCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C add Int M Test", dataProvider = "keyLength")
    public void addIntCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));


        assertEquals(keyPair.privateKey.decrypt(c1.add(m2)), m1.add(m2));
    }


    /**
     * todo Test addIntCipherIntCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C add Int C Test", dataProvider = "keyLength")
    public void addIntCipherIntCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        assertEquals(keyPair.privateKey.decrypt(c1.add(c2)), m1.add(m2));
    }

    /**
     * todo Test addIntCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C add Double M Test", dataProvider = "keyLength")
    public void addIntCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.add(m2));
        BigDecimal resultR = new BigDecimal(m1).add(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test addIntCipherDoubleCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C add Double C Test", dataProvider = "keyLength")
    public void addIntCipherDoubleCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.add(c2));
        BigDecimal resultR = new BigDecimal(m1).add(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test addDoubleCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C add Int M Test", dataProvider = "keyLength")
    public void addDoubleCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.add(m2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).add(new BigDecimal(m2));

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test addDoubleCipherIntCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C add Int C Test", dataProvider = "keyLength")
    public void addDoubleCipherIntCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.add(c2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).add(new BigDecimal(m2));

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test addDoubleCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C add Double M Test", dataProvider = "keyLength")
    public void addDoubleCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.add(m2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).add(m2);
        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test addDoubleCipherDoubleCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C add Double C Test", dataProvider = "keyLength")
    public void addDoubleCipherDoubleCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        BigDecimal resultL = ((BigDecimal) keyPair.privateKey.decrypt(c1.add(c2)));
        BigDecimal resultR = m1.add(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test subIntCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C sub Int M Test", dataProvider = "keyLength")
    public void subIntCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));


        assertEquals(keyPair.privateKey.decrypt(c1.subtract(m2)), m1.subtract(m2));
    }


    /**
     * todo Test subIntCipherIntCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C sub Int C Test", dataProvider = "keyLength")
    public void subIntCipherIntCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        assertEquals(keyPair.privateKey.decrypt(c1.subtract(c2)), m1.subtract(m2));
    }

    /**
     * todo Test subIntCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C sub Double M Test", dataProvider = "keyLength")
    public void subIntCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.subtract(m2));
        BigDecimal resultR = new BigDecimal(m1).subtract(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test subIntCipherDoubleCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C sub Double C Test", dataProvider = "keyLength")
    public void subIntCipherDoubleCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.subtract(c2));
        BigDecimal resultR = new BigDecimal(m1).subtract(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test subDoubleCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C sub Int M Test", dataProvider = "keyLength")
    public void subDoubleCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.subtract(m2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).subtract(new BigDecimal(m2));

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test subDoubleCipherIntCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C sub Int C Test", dataProvider = "keyLength")
    public void subDoubleCipherIntCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.subtract(c2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).subtract(new BigDecimal(m2));

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test subDoubleCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C sub Double M Test", dataProvider = "keyLength")
    public void subDoubleCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.subtract(m2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).subtract(m2);
        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test subDoubleCipherDoubleCipherTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C sub Double C Test", dataProvider = "keyLength")
    public void subDoubleCipherDoubleCipherTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c2 = keyPair.publicKey.encrypt(m2);

        BigDecimal resultL = ((BigDecimal) keyPair.privateKey.decrypt(c1.subtract(c2)));
        BigDecimal resultR = m1.subtract(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test mulIntCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C mul Int M Test", dataProvider = "keyLength")
    public void mulIntCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));

        assertEquals(keyPair.privateKey.decrypt(c1.multiply(m2)), m1.multiply(m2));
    }

    /**
     * todo Test mulIntCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C mul Double M Test", dataProvider = "keyLength")
    public void mulIntCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.multiply(m2));
        BigDecimal resultR = new BigDecimal(m1).multiply(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test mulDoubleCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C mul Int M Test", dataProvider = "keyLength")
    public void mulDoubleCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.multiply(m2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).multiply(new BigDecimal(m2));

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test mulDoubleCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C mul Double M Test", dataProvider = "keyLength")
    public void mulDoubleCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.multiply(m2));
        BigDecimal resultR = new BigDecimal(String.valueOf(m1)).multiply(m2);

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test divIntCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C div Int M Test", dataProvider = "keyLength")
    public void divIntCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.divide(m2));
        BigDecimal resultR = BigDecimal.valueOf(m1.doubleValue() / m2.doubleValue());

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Test divIntCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Int C div Double M Test", dataProvider = "keyLength")
    public void divIntCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigInteger m1 = randomInt(BigInteger.valueOf(keyLength));
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.divide(m2));
        BigDecimal resultR = BigDecimal.valueOf(m1.doubleValue() / m2.doubleValue());

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test divDoubleCipherIntPlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C div Int M Test", dataProvider = "keyLength")
    public void divDoubleCipherIntPlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        BigInteger m2 = randomInt(BigInteger.valueOf(keyLength));

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.divide(m2));
        BigDecimal resultR = BigDecimal.valueOf(m1.doubleValue() / m2.doubleValue());

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }


    /**
     * todo Test divDoubleCipherDoublePlainTest
     *
     * @param keyLength keypair length
     */
    @Test(description = "Double C div Double M Test", dataProvider = "keyLength")
    public void divDoubleCipherDoublePlainTest(int keyLength) {
        Paillier.PaillierKeyPair keyPair = Paillier.PaillierKeyPair.generate(keyLength);

        BigDecimal random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m1 = randomDec(BigInteger.valueOf(keyLength)).add(random);
        Paillier.EncryptedNumber c1 = keyPair.publicKey.encrypt(m1);

        random = BigDecimal.valueOf(new Random().nextDouble());
        BigDecimal m2 = randomDec(BigInteger.valueOf(keyLength)).add(random);

        BigDecimal resultL = (BigDecimal) keyPair.privateKey.decrypt(c1.divide(m2));
        BigDecimal resultR = BigDecimal.valueOf(m1.doubleValue() / m2.doubleValue());

        assertTrue(resultL.subtract(resultR).compareTo(BigDecimal.valueOf(1e-8)) <= 0);
    }

    /**
     * todo Private Function randomInt(BigInteger): generate random BigInteger
     *
     * @param n a bit length of BigInteger
     * @return BigInteger
     */
    @Contract("_ -> new")
    private @NotNull BigInteger randomInt(@NotNull BigInteger n) {
        Random rand = new Random();
        BigInteger result;
        do {
            result = new BigInteger(n.bitLength(), rand).abs();
        } while (result.equals(BigInteger.ZERO));

        return new BigInteger(n.bitLength(), rand);
    }

    /**
     * todo Private Function randomDec(BigInteger): generate random BigDecimal
     *
     * @param n a bit length of BigInteger
     * @return BigDecimal
     */
    @Contract("_ -> new")
    private @NotNull BigDecimal randomDec(BigInteger n) {
        return new BigDecimal(randomInt(n));
    }
}
