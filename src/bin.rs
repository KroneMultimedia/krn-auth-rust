extern crate krn_auth; // not needed since Rust edition 2018

use krn_auth::KRNAuth;

pub fn main() {
    let auth = KRNAuth{
        name: "KRN".to_string(),
        crypt_key: "".to_string(),
        hmac_secret: "".to_string(),
        rest_key: "".to_string(),
        rsa_key: "-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
".to_string()

    }; 
    let tk = "KRN:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJrcm4iLCJleHAiOjE2MjA3MjMzNTYsImlhdCI6MTYyMDcyMTU1NiwianRpIjoiNzUyYWYwMWEtZjEzYi00YTJhLWI5NDYtZWY2YzZkYjFiOTk0IiwicGF5bG9hZCI6IkxJck9wMHUycGpWUHZyMit1aC94NnlaV2dUMFV2dDZqSzhjYmxod1Z4ZWVaTHhHNWpzNVZYczJYbnhuNE1xckhRM1Iwd1NMUE5ML01TWllVeXVoSUl3OVV1R1gvZFRVZnUwZW1GZUVQcFp1bGVYZzJkMjVtNm5EdmFhZEtHWkJtMThYTHVhbC85VFR5ajFWSFl5dk4yTmdERkhhcHJlOHZpYitDalZxRUpIMEIrZ2pPVEVuak12eU5mNUR6YkdHQUw0SE41Z2xUVVFiNk1tMW1QYmFnbVNMWXEza2FOQUFjdUxhOWtlMGVjcFBocGdLRVNNaFM5Z2pVU3JPSmh3Mm4iLCJzdWIiOiI2MGUxNjZjZC1lMzQ5LTQxZjUtOGE0OS0xYTliODkzZTIzY2YifQ.KFsNghdby4wrqM2sIgLn67YhAJcAIQzGEeZ6PQ1vDaY".to_string();

    let resp = match auth.deep_validate(tk.clone()) {
        Ok(resp) => resp,
        Err(error) => panic!("Failed deep {:?}", error)
    };

    println!("Resp: {:?}", resp);

    let user = match auth.validate(tk.clone()) {
        Ok(user) => user,
        Err(error) => panic!("Failed {:?}", error)
    };
    println!("User: {:?}", user);
}
