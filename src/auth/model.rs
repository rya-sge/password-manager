use sqlite::Connection;
use argon2::Config;

pub fn add_user(connection: &Connection, username : &String, password: &String, privateKey : &String, publicKey : &String){
    //Insert username + hash in the database
    let mut statement = connection
        .prepare("INSERT INTO users VALUES (?, ?,?, ?)")
        .unwrap();

    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, password.as_str().clone()).unwrap();
    statement.bind(3, privateKey.as_str().clone()).unwrap();
    statement.bind(4, publicKey.as_str().clone()).unwrap();
    statement.next();
    println!("The user was successfully added");
}
pub fn add_password_database(connection: &Connection, username : &String, value: &String, label : &String){
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

pub fn check_password(username : &String, password : &String) -> bool {
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    //Search user in the database
    let mut statement = connection
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1,username.as_str().clone() ).unwrap();
    let result = statement.next();
    //Hash input password
    let salt = b"testtttt";

    //// Argon2 with default params (Argon2id v19)
    let config =  Config::default();
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
    return matches;
}
