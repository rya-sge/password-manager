extern crate read_input;
extern crate regex;
extern crate argon2;
extern crate rand;
extern crate sqlite;
extern crate pbkdf2;
extern crate openssl;

mod auth;

use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};
use argon2::Config;
use rand::{OsRng, Rng, StdRng, RngCore, FromEntropy};
use sqlite::State;
use crate::auth::signin;
use crate::auth::signup;


struct Password{
    label:String,
    password:String
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
