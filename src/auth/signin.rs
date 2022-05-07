use argon2::Config;
use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};

pub fn check_password(){

}

pub fn signin(){
    //Hash input password
    let salt = b"testtttt";

    //// Argon2 with default params (Argon2id v19)
    let config =  Config::default();
    let mut username;
    loop{
        let connection = sqlite::open("src/database/accounts.db").unwrap();
        //Get user credential
        println!("What is your username");
        username = input::<String>().get();
        //Search the username in the database
        println!("What is your master password");
        let password = input::<String>().get();

        //Search user in the database
        let mut statement = connection
            .prepare("SELECT * FROM users WHERE username = ?")
            .unwrap();
        statement.bind(1,username.as_str().clone() ).unwrap();
        let result = statement.next();


        let hash = argon2::hash_encoded(&password.as_bytes(), &*salt, &config).unwrap();
        let mut hash_db = username.as_bytes();
        let mut matches = false;
        //
        match result{
            Done =>{
                let find = statement.read::<String>(1);

                match find{
                    Ok(value)=>{
                        hash_db = value.as_bytes();
                        println!("OK {}", value);
                        matches = argon2::verify_encoded(&hash, &hash_db).unwrap();
                    }
                    Err(..)=>{
                        println!("Err");
                        //Username doesn't exist
                        argon2::verify_encoded(&hash, &hash_db).unwrap();
                    }
                }
            }
            Row=>{
                println!("This action is not possible");
            }

        }

        if !matches {
            println!("Connexion not possible");
        }else{
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
            1 => recover_password(&username),
            2 =>  add_password(&username),
            _ => panic!("Invalid input"),
        }
    }
}
fn change_master_password(){
    println!("Enter your password");
    let password = input::<String>().get();

    println!("Enter your new password");
    let new_password = input::<String>().get();

    let connection = sqlite::open("src/database/accounts.db").unwrap();
    //Search the username in the database
    let mut statement = connection
        .prepare("INSERT INTO password VALUES (?, ?, ?)")
        .unwrap();

    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, password.as_str().clone()).unwrap();
    statement.bind(3, new_password.as_str().clone()).unwrap();
    let result = statement.next();
    match result{
        Done =>{
            println!("Password added successfully");
        }
        Row =>{
            println!("An error has occured. Password could not be added");
        }
    }

}
fn add_password(username : &String){
    println!("Enter the label of the password");
    let label = input::<String>().get();

    println!("Enter the password");
    let value = input::<String>().get();

    let connection = sqlite::open("src/database/passwords.db").unwrap();
    //Search the username in the database
    let mut statement = connection
        .prepare("INSERT INTO password VALUES (?, ?, ?)")
        .unwrap();

    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, label.as_str().clone()).unwrap();
    statement.bind(3, value.as_str().clone()).unwrap();
    let result = statement.next();
    match result{
        Done =>{
            println!("Password added successfully");
        }
        Row =>{
            println!("An error has occured. Password could not be added");
        }
    }
}
fn recover_password(username : &String){
    println!("What label are you looking for?");
    let label = input::<String>().get();
    let connection = sqlite::open("src/database/passwords.db").unwrap();
    //Search the username in the database
    let mut statement = connection
        .prepare("SELECT * FROM password WHERE username = ? and label = ?")
        .unwrap();
    statement.bind(1, username.as_str().clone() ).unwrap();
    statement.bind(2, label.as_str().clone() ).unwrap();
    let result = statement.next();
    match result{
        Done =>{
            let find =  statement.read::<String>(2);
            match find{
                Ok(value)=>{
                    println!("Password is {}", value);
                }
                Err(..)=>{
                    //username is available
                    println!("No password found");
                }
            }
        }
        Row=>{
            println!("Impossible");
        }

    }
}
