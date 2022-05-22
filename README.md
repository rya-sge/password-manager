# Password manager
CAA labo 02

Modèle de menaces :



## Description of program

The user creates an account on the application. An RSA key pair is created and the RSA private key is encrypted with the key derived from the master password.

The hash of the master password is stored in the database.

When the user adds a new password to the database, it is encrypted with the RSA public key.

When  a user wishes to share a password with another user, he also uses the public key.



## Assets

| Name                        | Description                                                  | Protection                                              |
| --------------------------- | ------------------------------------------------------------ | ------------------------------------------------------- |
| RSA public key              | The RSA public key permet to encrypt a password              | no                                                      |
| RSA Private Key             | The RSA private key permet to decrypt a password             | Encrypt with KDF master password                        |
| Master password             | The master password unlocked the state of the program.       | Only the hash of the password is stored in the database |
| Derived Key master password | The KDF from master password is necessary to decrypt the RSA Private Key |                                                         |
|                             |                                                              |                                                         |
|                             |                                                              |                                                         |

## Algorithm

The hash of the master password is created with Argon2.

The KDF used to derived a key from password is PKDF. L'algorithme utilisé est différent de celui pour créer le hash car le hash est enregistré dans la base de donnée.



### Asymetric encryption

For the asymetric encryptc, it is the RSA algorithm. With a key of 2048 bits, it offers a satisfactory protection. It is easier to implement in Rust than an algorithm with elliptic curve.

For the padding, the library offers three different paddings : PKCS1, PKCS1_OAEP, PKCS1_PSS

- PKCS1 is not IND-CPA secure
- PKCS1_PSS_PADDING is designed for signature, not encryption
-  PKCS1_OAEP is IND-CCA2, but it is vulnerable to Manger’s attack.

Therefore, OAEP padding is used because it is the better solution between the three possibilities.

Link to documentation : [https://docs.rs/openssl/latest/src/openssl/rsa.rs.html#50](https://docs.rs/openssl/latest/src/openssl/rsa.rs.html#50)

Limitation

The Derived Key master password is vulnerable to side channel attack. Quand un utuilisateur est connecté, it is available in memory.

The attaquant can ainsi decrypt the RSA private key to then decrypt all passwords from the target user.

Rust :

