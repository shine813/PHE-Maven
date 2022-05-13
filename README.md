<h1 align='center' >PHE-Maven</h1>

<a href="https://github.com/shine813/PHE-Maven"><img src="https://img.shields.io/badge/phe_maven-1.0.0-green"></a>

---

## Background

<div align="justify">
The Paillier encryption system is a probabilistic public key encryption system invented by Paillier in 1999. 
Difficult problems based on composite residual classes. 
The encryption algorithm is a homomorphic encryption, which satisfies the homomorphism of addition and multiplication.

Based on [phe](https://github.com/data61/python-paillier) library (Paillier Homomorphic Encryption) using Java:

- generate key pair with 128, 256, 512, 1024, 2048, 3072 and 4096 key length
- encrypt int, long, float and double type number
- ciphertext addition (could be plaintext)
- ciphertext subtract (could be plaintext)
- ciphertext and plaintext multiplication
- ciphertext and plaintext division

---

## Environment

- `JDK15`
- `Maven3`

Package in `branches/mvn-repo`.

Maven in

```xml

<dependencies>
    <dependency>
        <groupId>cn.shine</groupId>
        <artifactId>PHE-Maven</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>

<repositories>
    <repository>
        <id>PHE-Maven</id>
        <url>https://raw.github.com/shine813/PHE-Maven/mvn-repo/</url>
    </repository>
</repositories>
```

See `pom.xml`。

---

## Example

See `src/main/java/cn/shine/APP.java`.

---

## Contact

Author: Shenyang Aerospace University-DSPC Zhan Shi

Github: https://github.com/shine813/

Email: phe.zshi@gmail.com

If you have any questions, please contact the author in time.

</div>
