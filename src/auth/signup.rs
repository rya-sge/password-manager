use read_input::prelude::input;
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Pbkdf2,
};
use crate::auth::model::add_user;
use openssl::rsa::{Rsa};
use openssl::symm::Cipher;
use crate::auth::constante::{ACCOUNTS_DB_USERNAME};
use argon2::{
    Argon2
};


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
    let salt_password_hash = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(&password.as_bytes(), &salt_password_hash).unwrap().to_string();

    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    assert!(Argon2::default().verify_password(&password.as_bytes(), &parsed_hash).is_ok());
    let salt_key_kdf = SaltString::generate(&mut OsRng);

    // Hash password to PHC string ($pbkdf2-sha256$...)
    let kdf_key = Pbkdf2.hash_password(password.as_bytes(), &salt_key_kdf);
    match kdf_key {
        Ok(val) => {
            assert!(Pbkdf2.verify_password(password.as_bytes(), &val).is_ok());
            //println!("KDF : {}", val.to_string());
            /* Create public and private RSA key*/
            let rsa = Rsa::generate(2048).unwrap();
            let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::chacha20_poly1305(), val.to_string().as_bytes()).unwrap();

            let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();
            let private_key_string = String::from_utf8(private_key).unwrap();
            let pub_key_string = String::from_utf8(public_key).unwrap();
            let salt_string = salt_key_kdf.as_str().to_string();

            add_user(&connection, &username, &password_hash, &private_key_string, &pub_key_string, &salt_string);
        }
        Err(err) => {
            println!("{}", err.to_string());
        }
    }
}
