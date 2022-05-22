use sqlite::{Connection, State};
use argon2::Config;
use openssl::rsa::{Rsa, Padding};
use std::str;
use crate::auth::constante::{ACCOUNTS_DB_PUBLIC_KEY, ACCOUNTS_DB_PASSWORD, RSA_PADDING_CHOICE};

pub fn add_user(connection: &Connection, username: &String, password: &String, privateKey: &String, publicKey: &String, saltKdf: &String) {
    //Insert username + hash in the database
    let mut statement = connection
        .prepare("INSERT INTO users VALUES (?, ?,?, ?, ?)")
        .unwrap();

    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, password.as_str().clone()).unwrap();
    statement.bind(3, publicKey.as_str().clone()).unwrap();
    statement.bind(4, privateKey.as_str().clone()).unwrap();
    statement.bind(5, saltKdf.as_str().clone()).unwrap();
    statement.next();
    println!("The user was successfully added");
}


pub fn add_password_database(connectionUser: &Connection, connectionPassword: &Connection, username: &String,
                             password: &String, label: &String) {
    //Search user in the database
    let mut statement = connectionUser
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone()).unwrap();
    let result_get_user = statement.next();

    match result_get_user {
        Ok(e) => {
            println!("Username found");
            let result_get_publicKey = statement.read::<String>(ACCOUNTS_DB_PUBLIC_KEY).unwrap();
            // Encrypt password with public key
            let rsa = Rsa::public_key_from_pem(result_get_publicKey.as_bytes()).unwrap();
            let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
            let _ = rsa.public_encrypt(password.as_bytes(), &mut buf, RSA_PADDING_CHOICE).unwrap();
            //println!("Encrypted: {:?}", buf);


            //Search the username in the database
            let mut statement = connectionPassword
                .prepare("INSERT INTO password VALUES (?, ?, ?)")
                .unwrap();

            statement.bind(1, username.as_str().clone()).unwrap();
            statement.bind(2, label.as_str().clone()).unwrap();
            //let bufferString = str::from(&buf).unwrap();
            let c: &[u8] = &buf;
            statement.bind(3, c).unwrap();
            let result = statement.next();
            match result {
                Ok(e) => {
                    println!("Password added successfully");
                }
                Err(e) => {
                    println!("An error has occured. Password could not be added");
                }
            }
        }
        Err(e) => {
            println!("An error has occured. Password could not be added");
        }
    }
}

pub fn hashPassword(password: &String) -> String {
    //Hash input password
    let salt = b"testtttt";

    //// Argon2 with default params (Argon2id v19)
    let config = Config::default();
    let hash = argon2::hash_encoded(&password.as_bytes(), &*salt, &config).unwrap();
    return hash;
}

pub fn check_password(username: &String, password: &String) -> bool {
    let mut matches = false;

    /* search user - begin */
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    //Search user in the database
    let mut statement = connection
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone()).unwrap();
    let result = statement.next();
    /* search user - end */

    match result {
        Ok(val) => {
            let mut hash_db = username.as_bytes();
            let hash = hashPassword(&password);
            //
            let find = statement.read::<String>(ACCOUNTS_DB_PASSWORD);
            match find {
                Ok(value) => {
                    hash_db = value.as_bytes();
                    println!("OK {}", value);
                    matches = argon2::verify_encoded(&hash, &hash_db).unwrap();
                }
                Err(..) => {
                    println!("Err");
                    //Username doesn't exist
                    argon2::verify_encoded(&hash, &hash_db).unwrap();
                }
            }
        }
        Err(e) => {
            println!("This action is not possible");
        }
    }
    return matches;
}
