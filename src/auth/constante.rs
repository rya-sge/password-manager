use openssl::rsa::{Padding};

pub static PASSWORD_DB_LABEL: usize = 1;
pub static PASSWORD_DB_VALUE: usize = 2;
pub static ACCOUNTS_DB_USERNAME: usize = 0;
pub static ACCOUNTS_DB_PASSWORD: usize = 1;
pub static ACCOUNTS_DB_PUBLIC_KEY: usize = 2;
pub static ACCOUNTS_DB_PRIVATE_KEY: usize = 3;
pub static ACCOUNTS_DB_KDF_SALT: usize = 4;
pub static RSA_PADDING_CHOICE: Padding = Padding::PKCS1;
