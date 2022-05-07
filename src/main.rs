extern crate read_input;
extern crate regex;
extern crate argon2;
extern crate rand;
extern crate sqlite;


use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::Write;
use argon2::Config;
use rand::{OsRng, Rng, StdRng, RngCore, FromEntropy};
use sqlite::State;

struct Categorie{
    label:String,
    regex:String
}

struct Password{
    label:String,
    password:String
}


fn signin(){

}

fn generateSalt(){


}
fn signup(){
    let separator = "END";
    let mut username;
    loop{
        println!("What is your username");
        username = input::<String>().get();
        //the username musn't contain the separtor
        if !username.contains(separator) {
            break
        }else{
            println!("The username mustn't contain {}", separator);
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

    let newLine = username.clone() + "END" + hash.as_str();
    println!("{}",hash);
    let matches = argon2::verify_encoded(&hash, &password.as_bytes()).unwrap();
    assert!(matches);

    let connection = sqlite::open("src/database/accounts.db").unwrap();
    let mut statement = connection
        .prepare("INSERT INTO users VALUES (?, ?)")
        .unwrap();

    let us = username.as_str().clone();
    let ps = password.as_str().clone();
    statement.bind(1,us ).unwrap();
    statement.bind(2, ps).unwrap();
    statement.next();


}

fn main() {

    //let mut list_password = Vec::new();
    println!("Hello to the best password manager");
    loop {
        match input::<u32>().repeat_msg("What do you want to do?\n1 - signin\n2 - signup\n0 - quit\nYour input ? [0-2]")
            .min_max(0, 2).get() {
            0 => {
                println!("Goodbye!");
                break
            },
            1 => signin(),
            2 => signup(),
            _ => panic!("Invalid input"),
        }
    }
}
