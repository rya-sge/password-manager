use read_input::prelude::input;
use argon2::Config;

pub fn signup(){
    let mut username;
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    loop{
        println!("What is your username");
        username = input::<String>().get();
        //Search the username in the database
        let mut statement = connection
            .prepare("SELECT * FROM users WHERE username = ?")
            .unwrap();
        statement.bind(1,username.as_str().clone() ).unwrap();
        let result = statement.next();
        match result{
            Done =>{
                let find =  statement.read::<String>(0);
                match find{
                    Ok(..)=>{
                        println!("It is not possible to create an account with this username");
                    }
                    Err(..)=>{
                        //username is available
                        break;
                    }
                }
            }
            Row=>{
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
    let config =  Config::default();

    let hash = argon2::hash_encoded(&password.as_bytes(), &*salt, &config).unwrap();
    println!("{}",hash);
    let matches = argon2::verify_encoded(&hash, &password.as_bytes()).unwrap();
    assert!(matches);

    //Create public and private RSA key
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    //Insert username + hash in the database
    let connection = sqlite::open("src/database/accounts.db").unwrap();
    let mut statement = connection
        .prepare("INSERT INTO users VALUES (?, ?)")
        .unwrap();

    statement.bind(1, username.as_str().clone()).unwrap();
    statement.bind(2, password.as_str().clone()).unwrap();
    statement.next();
}
