use sqlite::{Connection, State};
use argon2::Config;
use openssl::rsa::Padding;

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
pub fn add_password_database(connectionUser : &connection, connectionPassword: &Connection, username : &String, password_hash: &String, label : &String){
    //Search user in the database
    let mut statement = connectionUser
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1,username.as_str().clone() ).unwrap();
    let result_get_user =  statement.next();

    match result_get_user {
        Result::State::Done  =>{
            println!("Username found");
            let result_get_publicKey = statement.read::<String>(2);
            // Encrypt password with public key
            let rsa = Rsa::public_key_from_pem(result_get_publicKey.as_bytes()).unwrap();
            let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
            let _ = rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
            println!("Encrypted: {:?}", buf);

            let data = buf;

            //Search the username in the database
            let mut statement = connectionPassword
                .prepare("INSERT INTO password VALUES (?, ?, ?)")
                .unwrap();

            statement.bind(1, username.as_str().clone()).unwrap();
            statement.bind(2, label.as_str().clone()).unwrap();
            statement.bind(3, password_hash.as_str().clone()).unwrap();
            let result = statement.next();
            match result{
                Result::State::Done  =>{
                    println!("Password added successfully");
                }
                Result::State::Row =>{
                    println!("An error has occured. Password could not be added");
                }
            }

        }
        Result::State::Row =>{
            println!("An error has occured. Password could not be added");
        }
    }

}
pub fn hashPassword(password : &string) -> String {
    //Hash input password
    let salt = b"testtttt";

    //// Argon2 with default params (Argon2id v19)
    let config =  Config::default();
    let hash = argon2::hash_encoded(&password.as_bytes(), &*salt, &config).unwrap();
    return hash;
}
pub fn check_password(username : &String, password : &String) -> bool {
    let mut matches = false;

    /* search user - begin */
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    //Search user in the database
    let mut statement = connection
        .prepare("SELECT * FROM users WHERE username = ?")
        .unwrap();
    statement.bind(1,username.as_str().clone() ).unwrap();
    let result = statement.next();
    /* search user - end */

    match result{
        Result::State::Done  =>{

            let mut hash_db = username.as_bytes();
            let hash = hashPassword(&password);
            //
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
