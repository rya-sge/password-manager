use sqlite::{Connection};
use openssl::rsa::{Rsa};
use crate::auth::constante::{ACCOUNTS_DB_PUBLIC_KEY, ACCOUNTS_DB_PASSWORD, RSA_PADDING_CHOICE};
use argon2::{
    password_hash::{
        PasswordHash, PasswordVerifier
    },
    Argon2
};

pub fn add_user(connection: &Connection, username: &String, password: &String, private_key: &String, public_key: &String, salt_kdf: &String) {
    //Insert username + hash in the database
    let mut statement = connection
        .prepare("INSERT INTO users VALUES (?, ?,?, ?, ?)")
        .unwrap();

    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, password.as_str().clone()).unwrap();
    statement.bind(3, public_key.as_str().clone()).unwrap();
    statement.bind(4, private_key.as_str().clone()).unwrap();
    statement.bind(5, salt_kdf.as_str().clone()).unwrap();
    statement.next();
    println!("The user was successfully added");
}


pub fn add_password_database(connection_user: &Connection, connection_password: &Connection, username: &String,
                             password: &String, label: &String) {
    //Search user in the database
    let mut statement = connection_user
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone()).unwrap();
    let result_get_user = statement.next();

    match result_get_user {
        Ok(_e) => {
            println!("Username found");
            let result_get_public_key = statement.read::<String>(ACCOUNTS_DB_PUBLIC_KEY).unwrap();
            // Encrypt password with public key
            let rsa = Rsa::public_key_from_pem(result_get_public_key.as_bytes()).unwrap();
            let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
            let _ = rsa.public_encrypt(password.as_bytes(), &mut buf, RSA_PADDING_CHOICE).unwrap();
            //println!("Encrypted: {:?}", buf);


            //Search the username in the database
            let mut statement = connection_password
                .prepare("INSERT INTO password VALUES (?, ?, ?)")
                .unwrap();

            statement.bind(1, username.as_str().clone()).unwrap();
            statement.bind(2, label.as_str().clone()).unwrap();
            //let bufferString = str::from(&buf).unwrap();
            let c: &[u8] = &buf;
            statement.bind(3, c).unwrap();
            let result = statement.next();
            match result {
                Ok(_e) => {
                    println!("Password added successfully");
                }
                Err(_e) => {
                    println!("An error has occured. Password could not be added");
                }
            }
        }
        Err(_e) => {
            println!("An error has occured. Password could not be added");
        }
    }
}

pub fn check_password(connection : &Connection, username: &String, password: &String) -> bool {
    let mut matches = false;

    /* search user - begin */
    //Search user in the database
    let mut statement = connection
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone()).unwrap();
    let result = statement.next();
    /* search user - end */

    match result {
        Ok(_val) => {
            let hash_db =  statement.read::<String>(ACCOUNTS_DB_PASSWORD).unwrap();
            let parsed_hash = PasswordHash::new(&hash_db).unwrap();
            matches = Argon2::default().verify_password(&password.as_bytes(), &parsed_hash).is_ok();
        }
        Err(_e) => {
            println!("This action is not possible");
        }
    }
    return matches;
}
