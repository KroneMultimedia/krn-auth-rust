extern crate base64;
extern crate openssl;
extern crate serde_json;

use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::str;

use self::openssl::symm::*;

//Global error + conversions
#[derive(Serialize, Deserialize, Debug)]
pub enum KRNAuthErrors {
    TokenInvalid,
}

#[derive(Debug, Serialize, Deserialize)]
struct KRNClaims {
    aud: String,
    sub: String,
    exp: usize,
    iat: usize,
    jti: String,
    payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KRNAuth {
    pub name: String,
    pub crypt_key: String,
    pub hmac_secret: String,
    pub rest_key: String,
    pub rsa_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KRNUser {
    pub nick_name: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub flags: i64,
    pub id: String,
    pub int_id: i64,
}

impl KRNAuth {
    pub fn deep_validate(&self, passport: String) -> Result<String, KRNAuthErrors> {
        let url = format!(
            "https://trinity.krone.at/deep-validate?token={}",
            passport
        );
        let client = reqwest::blocking::Client::new();
        let resp = client.post(url).send().unwrap();

        if resp.status() == 200 {
            Ok(resp.text().unwrap().to_string())
        } else {
            Err(KRNAuthErrors::TokenInvalid)
        }
    }
    pub fn validate(self, passport: String) -> Result<KRNUser, KRNAuthErrors> {
        let token_parts: Vec<&str> = passport.split(":").collect();

        let decoded = decode::<KRNClaims>(
            &token_parts[1],
            &DecodingKey::from_secret(self.hmac_secret.as_ref()),
            &Validation::default(),
        )
        .unwrap();

        let payload = self
            .decode_payload(decoded.claims.payload.to_string())
            .unwrap();
        Ok(payload)
    }
    pub fn decode_payload(self, payload: String) -> Result<KRNUser, KRNAuthErrors> {
        let payload_base64 = base64::decode(&payload).unwrap();

        let iv_size = 16;
        let iv = &payload_base64[0..iv_size];
        let enc_data = &payload_base64[iv_size..];
        let mut decrypter = Crypter::new(
            Cipher::aes_256_cbc(),
            Mode::Decrypt,
            &self.crypt_key.as_bytes(),
            Some(&iv),
        )
        .unwrap();
        decrypter.pad(false);
        let mut decrypted = vec![0u8; 400];
        decrypter
            .update(&enc_data, decrypted.as_mut_slice())
            .unwrap();

        let decrypted_json = str::from_utf8(&decrypted[0..enc_data.len()]).unwrap();

        // WHAT IS THIS?
        let s = decrypted_json.replace("\u{6}", "");

        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        let u = KRNUser {
            nick_name: v["NickName"].to_string(),
            email: v["Email"].to_string(),
            first_name: v["FirstName"].to_string(),
            last_name: v["LastName"].to_string(),
            flags: v["Flags"].as_i64().unwrap(),
            int_id: v["IntID"].as_i64().unwrap(),
            id: v["ID"].to_string(),
        };
        Ok(u)
    }
}
