use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};
use crate::auth::model::add_password_database;
use crate::auth::model::check_password;
use openssl::rsa::{Rsa};
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::PasswordHasher;
use crate::auth::constante::{PASSWORD_DB_LABEL, PASSWORD_DB_VALUE, ACCOUNTS_DB_PRIVATE_KEY,
                             ACCOUNTS_DB_KDF_SALT, RSA_PADDING_CHOICE};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use openssl::symm::Cipher;

pub fn signin() {
    let mut username;
    let key_kdf;
    let connection_accounts = sqlite::open("src/database/accounts.db").unwrap();
    let connection_account = sqlite::open("src/database/accounts.db").unwrap();
    loop {
        //Get user credential
        println!("What is your username");
        username = input::<String>().get();
        //Search the username in the database
        println!("What is your master password");
        let password = input::<String>().get();


        let matches = check_password(&connection_accounts, &username, &password);

        if !matches {
            println!("Connexion not possible");
        } else {

            //Search user in the database
            let mut statement = connection_account
                .prepare("SELECT * FROM users WHERE username = ?")
                .unwrap();
            statement.bind(1, username.as_str().clone()).unwrap();
            let result = statement.next();
            match result {
                Ok(_val) => {
                    let salt = statement.read::<String>(ACCOUNTS_DB_KDF_SALT).unwrap();
                    key_kdf = Pbkdf2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
                    break;
                }
                Err(_e) => {
                    println!("Connection not possible");
                }
            }
        }
    }

    println!("You are in Unlocked State");

    loop {
        match input::<u32>().repeat_msg("What do you want to do?\n1 - Recover a password\n2 - add a new password\n3 - Changer master password\n4 - Share a password\n0 - quit\nYour input ? [0-4]")
            .min_max(0, 4).get() {
            0 => {
                println!("Goodbye!");
                break;
            }
            1 => recover_password(&username, &key_kdf),
            2 => add_password(&username),
            3 => change_master_password(&username, &key_kdf),
            4 => shared_password(&username, &key_kdf),
            _ => panic!("Invalid input"),
        }
    }
}

fn shared_password(username: &String, kdf_key: &String) {
    loop {
        println!("Enter the user you want to share your password with");
        let username_target = input::<String>().get();

        let connection_account = sqlite::open("src/database/accounts.db").unwrap();
        //Search user in the database
        let mut statement = connection_account
            .prepare("SELECT * FROM users WHERE username = ?")
            .unwrap();
        statement.bind(1, username_target.as_str().clone()).unwrap();
        let result_get_user = statement.next();
        match result_get_user {
            Ok(result_get_user_val) => {
                match result_get_user_val {
                    sqlite::State::Done => {
                        println!("Username not found");
                        break;
                    }
                    sqlite::State::Row => {
                        let connection_password = sqlite::open("src/database/passwords.db").unwrap();
                        println!("Enter the password label to shared");
                        let label = input::<String>().get();

                        let mut statement = connection_password
                            .prepare("SELECT * FROM password WHERE username = ? and label = ?")
                            .unwrap();
                        statement.bind(1, username.as_str().clone()).unwrap();
                        statement.bind(2, label.as_str().clone()).unwrap();
                        let result_get_password = statement.next();
                        println!("password get");
                        match result_get_password {
                            Ok(_e) => {
                                let get_password = statement.read::<Vec<u8>>(PASSWORD_DB_VALUE);
                                let get_label = statement.read::<String>(PASSWORD_DB_LABEL);
                                match get_password {
                                    Ok(value) => {
                                        match get_label {
                                            Ok(label) => {
                                                println!("Label is {}", label);
                                                //Get the  private key
                                                let mut statement_account = connection_account
                                                    .prepare("SELECT * FROM users WHERE username = ?")
                                                    .unwrap();
                                                statement_account.bind(1, username.as_str().clone()).unwrap();
                                                statement_account.next().unwrap();
                                                let get_private_key = statement_account.read::<String>(ACCOUNTS_DB_PRIVATE_KEY).unwrap();

                                                // Decrypt the password with private key
                                                let rsa = Rsa::private_key_from_pem_passphrase(get_private_key.as_bytes(), &kdf_key.as_bytes()).unwrap();
                                                let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
                                                rsa.private_decrypt(&value, &mut buf, RSA_PADDING_CHOICE).unwrap();

                                                /* TODO: Don't work */
                                                let res = String::from_utf8(buf).unwrap();
                                                add_password_database(&connection_account, &connection_password, &username_target, &res, &label);

                                            }
                                            Err(..) => {
                                                //username is available
                                                println!("No label found found");
                                            }
                                        }
                                    }
                                    Err(..) => {
                                        //username is available
                                        println!("No password found");
                                    }
                                }
                            }
                            Err(_e) => {
                                println!("No password found");
                            }
                        }



                    }
                }
            }
            _ => {
                println!("Error. Action not possible");
            }
        }
    }
}

fn change_master_password(username: &String, old_key_kdf: &String) {
    let mut password;
    let connection_accounts = sqlite::open("src/database/accounts.db").unwrap();
    loop {
        println!("Enter your password");
        password = input::<String>().get();

        let matches = check_password(&connection_accounts, &username, &password);

        if !matches {
            println!("Password incorrect");
        } else {
            break;
        }
    }

    println!("Enter your new password");
    let new_password = input::<String>().get();

    // Change password
    let connection_accounts = sqlite::open("src/database/accounts.db").unwrap();
    let salt_password_hash = SaltString::generate(&mut OsRng);
    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();
    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(&new_password.as_bytes(),
                                             &salt_password_hash).unwrap().to_string();
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    assert!(Argon2::default().verify_password(&new_password.as_bytes(), &parsed_hash).is_ok());


    //Generate master key for encryption
    let salt_key_kdf = SaltString::generate(&mut OsRng);
    let salt_key_kdf_string = salt_key_kdf.as_str().to_string();
    // Hash password to PHC string ($pbkdf2-sha256$...)
    let kdf_key = Pbkdf2.hash_password(&new_password.as_bytes(), &salt_key_kdf);
    match kdf_key {
        Ok(val) => {
            assert!(Pbkdf2.verify_password(&new_password.as_bytes(), &val).is_ok());

            let mut statement_account = connection_accounts
                .prepare("SELECT * FROM users WHERE username = ?")
                .unwrap();
            statement_account.bind(1, username.as_str().clone()).unwrap();
            statement_account.next().unwrap();
            // Get private key
            let get_private_key = statement_account.read::<String>(ACCOUNTS_DB_PRIVATE_KEY).unwrap();
            // Decrypt the private key
            let rsa = Rsa::private_key_from_pem_passphrase(get_private_key.as_bytes(),
                                                           &old_key_kdf.as_bytes()).unwrap();


            //Encrypt private key with passphrase
            let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(Cipher::chacha20_poly1305(),
                                                                         val.to_string().as_bytes()).unwrap();
            let private_key_string = String::from_utf8(private_key).unwrap();

            //Update the user in the database
            let mut statement = connection_accounts
                .prepare("UPDATE users set password = ?, privateKey = ?, kdfSalt = ? WHERE username = ?")
                .unwrap();

            statement.bind(1, password_hash.as_str().clone()).unwrap();
            statement.bind(2, private_key_string.as_str().clone()).unwrap();
            statement.bind(3, salt_key_kdf_string.as_str().clone()).unwrap();
            statement.bind(4, username.as_str().clone()).unwrap();

            let result = statement.next();
            match result {
                Ok(_val) => {
                    println!("Password changed successfully. You need to log again");
                    panic!("No other solution found")
                }
                Err(_e) => {
                    println!("An error has occured. The password could not be updated");
                }
            }
        }
        Err(err) => {
            println!("{}", err.to_string());
        }
    }
}

fn add_password(username: &String) {
    let connection_password = sqlite::open("src/database/passwords.db").unwrap();
    let connection_account = sqlite::open("src/database/accounts.db").unwrap();
    println!("Enter the label of the password");
    let label = input::<String>().get();

    println!("Enter the password");
    let value = input::<String>().get();

    add_password_database(&connection_account, &connection_password, &username, &value, &label);
}


fn recover_password(username: &String, key_kdf: &String) {
    println!("What label are you looking for?");
    let label = input::<String>().get();
    let connection_password = sqlite::open("src/database/passwords.db").unwrap();
    //Search the username in the database
    let connection_accounts = sqlite::open("src/database/accounts.db").unwrap();
    let mut statement = connection_password
        .prepare("SELECT * FROM password WHERE username = ? and label = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, label.as_str().clone()).unwrap();
    let result = statement.next();
    match result {
        Ok(_value) => {
            let find = statement.read::<Vec<u8>>(PASSWORD_DB_VALUE);
            match find {
                Ok(value) => {
                    let mut statement_account = connection_accounts
                        .prepare("SELECT * FROM users WHERE username = ?")
                        .unwrap();
                    statement_account.bind(1, username.as_str().clone()).unwrap();
                    statement_account.next().unwrap();
                    let get_private_key = statement_account.read::<String>(ACCOUNTS_DB_PRIVATE_KEY).unwrap();
                    // Decrypt with private key
                    let rsa = Rsa::private_key_from_pem_passphrase(get_private_key.as_bytes(),
                                                                   &key_kdf.as_bytes()).unwrap();
                    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
                    rsa.private_decrypt(&value, &mut buf, RSA_PADDING_CHOICE).unwrap();
                    println!("Decrypted: {}", String::from_utf8(buf).unwrap());
                }
                Err(..) => {
                    //username is available
                    println!("No password found");
                }
            }
        }
        Err(_e) => {
            println!("Impossible");
        }
    }
}
