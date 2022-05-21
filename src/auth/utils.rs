use openssl::rsa::Padding;

pub fn decryptPassword(private_key_pem : &String, passwordToDecrypt : &String, mut password_result: &String,
                       &kdf_key : &String){
    let rsa = Rsa::private_key_from_pem_passphrase(private_key_pem.as_bytes(), &kdf_key.as_bytes()).unwrap();
    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
    password_result = rsa.private_decrypt(passwordToDecrypt, &mut buf, Padding::PKCS1).unwrap();
}

/*pub fn encryptPassword(result_get_publicKey : &String, mut buf: &Vec<u8>,
                       &kdf_key : &String){
    // Encrypt password with public key
    let rsa = Rsa::public_key_from_pem(result_get_publicKey.as_bytes()).unwrap();

    let _ = rsa.public_encrypt(password.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
    println!("Encrypted: {:?}", buf);

    let data = buf;
}*/

