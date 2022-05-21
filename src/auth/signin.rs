use argon2::Config;
use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};
use sqlite::{State, Statement, Connection};
use crate::auth::model::add_password_database;
use crate::auth::model::check_password;
use openssl::rsa::{Rsa, Padding};
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::PasswordHasher;

pub fn signin(){
    let mut username;
    let mut key_kdf;
    loop{
        let connection = sqlite::open("src/database/accounts.db").unwrap();
        //Get user credential
        println!("What is your username");
        username = input::<String>().get();
        //Search the username in the database
        println!("What is your master password");
        let password = input::<String>().get();


        let matches = check_password(&username, &password);

        if !matches {

            println!("Connexion not possible");
        }else{
            let connectionAccount = sqlite::open("src/database/accounts.db").unwrap();
            //Search user in the database
            let mut statement = connectionAccount
                .prepare("SELECT * FROM users WHERE username = ?")
                .unwrap();
            statement.bind(1,username.as_str().clone() ).unwrap();
            let salt = statement.read::<String>(4).unwrap();
            key_kdf =  Pbkdf2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
            break;
        }
    }

    println!("You are in Unlocked State");

    loop {
        match input::<u32>().repeat_msg("What do you want to do?\n1 - Recover a password\n2 - add a new password\n3 - Changer master password\n4 - Share a password\n0 - quit\nYour input ? [0-2]")
            .min_max(0, 4).get() {
            0 => {
                println!("Goodbye!");
                break
            },
            1 => recover_password(&username, &key_kdf ),
            2 => add_password(&username),
            3 => change_master_password(&username),
            4 => shared_password(&username, &key_kdf),
            _ => panic!("Invalid input"),
        }
    }
}
fn shared_password(username : &String, kdf_key: &String){
    loop{
        println!("Enter the user you want to share your password with");
        let usernameTarget = input::<String>().get();

        let connectionAccount = sqlite::open("src/database/accounts.db").unwrap();
        //Search user in the database
        let mut statement = connectionAccount
            .prepare("SELECT * FROM users WHERE username = ?")
            .unwrap();
        statement.bind(1,usernameTarget.as_str().clone() ).unwrap();
        let result_get_user =  statement.next();
        let result_get_user_name = statement.read::<String>(0);
        let getPrivateKey = statement.read::<String>(2).unwrap();
        let result_get_password;
        match result_get_user_name {
            Ok (e) => {
                //println!("Enter the password label to shared {}");
                //Get the public key of the user
                let connectionPassword = sqlite::open("src/database/passwords.db").unwrap();
                println!("Enter the password label to shared");
                let label = input::<String>().get();

                let mut statement = connectionPassword
                    .prepare("SELECT * FROM password WHERE username = ? and label = ?")
                    .unwrap();
                statement.bind(1, username.as_str().clone() ).unwrap();
                statement.bind(2, label.as_str().clone() ).unwrap();
                result_get_password = statement.next();
                println!("password get");

                match result_get_password {
                    Ok(t)=> {
                        let getPassword = statement.read::<String>(2);
                        let getLabel = statement.read::<String>(1);
                        match getPassword {
                            Ok(value) => {
                                // Decrypt with private key
                                let mut passwordDecrypt = "";
                                //decryptPassword(&getPrivateKey, &value,&passwordDecrypt.to_str(),
                                                //&kdf_key);
                                let rsa = Rsa::private_key_from_pem_passphrase(getPrivateKey.as_bytes(), &kdf_key.as_bytes()).unwrap();
                                let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
                                rsa.private_decrypt(value.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
                                //println!("Decrypted: {}", String::from_utf8(buf).unwrap());
                                //println!("Decrypted: {}",String::from_utf8(buf).unwrap());

                                println!("Password is {}", value);
                                match getLabel {
                                    Ok(label) => {
                                        println!("Label is {}", label);
                                        //let connection = sqlite::open("src/database/passwords.db").unwrap();
                                        //Search the username in the database
                                        //Search the username in the database
                                        //let connection = sqlite::open("src/database/passwords.db").unwrap();
                                        add_password_database(&connectionAccount, &connectionPassword, &usernameTarget, &String::from_utf8(buf).unwrap(), &label);
                                    }
                                    Err(..) => {
                                        //username is available
                                        println!("No label found found");
                                    }
                                }

                                //Decrypt passwword with private key
                                //Encrypt password with public key
                            }
                            Err(..) => {
                                //username is available
                                println!("No password found");
                            }
                        }
                    }Err(e) =>{
                        println!("Error has occured");
                    }

                }
            }
            Err(e) =>{
                println!("This action is not possible");
            }

        }

    }
}
fn change_master_password(username : &String){
    let mut password;
    loop{
        println!("Enter your password");
        password = input::<String>().get();

        let matches = check_password(&username, &password);

        if !matches {
            println!("Password incorrect");
        }else{
            break;
        }
    }

    println!("Enter your new password");
    let new_password = input::<String>().get();

    let connectionAccounts = sqlite::open("src/database/accounts.db").unwrap();
    //Search the username in the database
    let mut statement = connectionAccounts
        .prepare("UPDATE users set password = ? WHERE username = ?")
        .unwrap();

    statement.bind(1, new_password.as_str().clone()).unwrap();
    statement.bind(2, username.as_str().clone()).unwrap();

    let result = statement.next();
    match result{
        Ok(val)=>{
            println!("Password changed successfully");
        }
        Err(e) =>{
            println!("An error has occured. The password could not be updated");
        }
    }

}


fn add_password(username : &String){
    let connectionPassword = sqlite::open("src/database/passwords.db").unwrap();
    let connectionAccount = sqlite::open("src/database/accounts.db").unwrap();
    println!("Enter the label of the password");
    let label = input::<String>().get();

    println!("Enter the password");
    let value = input::<String>().get();

    add_password_database(&connectionAccount, &connectionPassword, &username, &value, &label);
}


fn recover_password(username : &String, key_kdf : &String){
    println!("What label are you looking for?");
    let label = input::<String>().get();
    let connection = sqlite::open("src/database/passwords.db").unwrap();
    //Search the username in the database
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    let mut statement = connection
        .prepare("SELECT * FROM password WHERE username = ? and label = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone() ).unwrap();
    statement.bind(2, label.as_str().clone() ).unwrap();
    let result = statement.next();
    match result{
        Ok(value)=>{
            let find =  statement.read::<String>(2);
            match find{
                Ok(value)=>{
                    let getPrivateKey = statement.read::<String>(2).unwrap();
                    // Decrypt with private key
                    let mut passwordDecrypt = "";
                    /*decryptPassword(&getPrivateKey, &value,&passwordDecrypt.to_str(),
                                    &kdf_key);*/
                    let rsa = Rsa::private_key_from_pem_passphrase(getPrivateKey.as_bytes(), &key_kdf.as_bytes()).unwrap();
                    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
                    rsa.private_decrypt(value.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
                    //println!("Decrypted: {}", String::from_utf8(buf).unwrap());
                    println!("Decrypted: {}",String::from_utf8(buf).unwrap());
                    println!("Password is {}", value);
                }
                Err(..)=>{
                    //username is available
                    println!("No password found");
                }
            }
        }
       Err(e)=>{
            println!("Impossible");
        }

    }
}
