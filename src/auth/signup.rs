use read_input::prelude::input;
use argon2::Config;
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Pbkdf2,
};
use pbkdf2::password_hash::Error;
use crate::auth::model::add_user;
use openssl::rsa::{Rsa, Padding};
use openssl::symm::Cipher;
use crate::auth::constante::{ACCOUNTS_DB_USERNAME, RSA_PADDING_CHOICE};


pub fn signup() {
    let mut username;
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    loop {
        println!("What is your username");
        username = input::<String>().get();
        //Search the username in the database
        let mut statement = connection
            .prepare("SELECT * FROM users WHERE username = ?")
            .unwrap();
        statement.bind(1, username.as_str().clone()).unwrap();
        let result = statement.next();
        match result {
            Ok(_val) => {
                let find = statement.read::<String>(ACCOUNTS_DB_USERNAME);
                match find {
                    Ok(..) => {
                        println!("It is not possible to create an account with this username");
                    }
                    Err(..) => {
                        //username is available
                        break;
                    }
                }
            }
            Err(_e) => {
                println!("not possible");
            }
        }
    }

    println!("What is your master password");
    let password = input::<String>().get();

    //Size salt of 128 bits
    //https://www.ory.sh/choose-recommended-argon2-parameters-password-hashing/
    let salt = b"testtttt";

    //// Argon2 with default params (Argon2id v19)
    let config = Config::default();

    let hash = argon2::hash_encoded(&password.as_bytes(), &*salt, &config).unwrap();
    println!("{}", hash);
    let matches = argon2::verify_encoded(&hash, &password.as_bytes()).unwrap();
    assert!(matches);


    let salt = SaltString::generate(&mut OsRng);

    // Hash password to PHC string ($pbkdf2-sha256$...)
    let kdf_key = Pbkdf2.hash_password(password.as_bytes(), &salt);
    match kdf_key {
        Ok(val) => {
            assert!(Pbkdf2.verify_password(password.as_bytes(), &val).is_ok());
            println!("KDF : {}", val.to_string());
            /*//Create public and private RSA key*/
            /*let mut rng = rand::thread_rng();
            let bits = 2048;
            let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
            let pub_key = RsaPublicKey::from(&priv_key);*/
            let rsa = Rsa::generate(2048).unwrap();
            let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::chacha20_poly1305(), val.to_string().as_bytes()).unwrap();
            //let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::chacha20_poly1305(), essai.as_bytes()).unwrap();
            //let convert = String::from_utf8(private_key).unwrap();

            let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();


            //let privateK = .;
            //let _test = Rsa::private_key_from_pem_passphrase(String::from_utf8(private_key).unwrap().as_bytes(), essai.as_bytes()).unwrap();
            //let pubK = String::from_utf8(public_key).unwrap();
            //println!("Private key: {}", privateK);
            ///println!("Public key: {}", pubK);
            //let strSalt = salt.as_str().to_string();
            let privateK = String::from_utf8(private_key).unwrap();
            let pubK = String::from_utf8(public_key).unwrap();
            println!("Private key: {}", privateK);
            println!("Public key: {}", pubK);
            let strSalt = salt.as_str().to_string();

            add_user(&connection, &username, &password, &privateK, &pubK, &strSalt);
        }
        Err(err) => {
            println!("{}", err.to_string());
        }
    }
// Verify password against PHC string
}
