use digital_signature::{
    database::{AccountInfo, InMemDB},
    request::{Acct, SignedMessage},
    response::RegResponse,
};
use rocket::{http::Status, serde::json::Json, State};

#[macro_use]
extern crate rocket;

#[post("/register", format = "json", data = "<acct>")]
fn register_user(db: &State<InMemDB>, acct: Json<Acct>) -> (Status, Json<RegResponse>) {
    let mut locked_db = db.db.lock().unwrap();
    let v = match AccountInfo::new(acct.public_key.replace("\n", "\r\n")) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e.message);
            return (
                Status::NotAcceptable,
                Json(RegResponse {
                    account_name: String::from(&acct.account_name),
                    nonce: 0,
                    message: String::from("Unable to use Public Key"),
                }),
            );
        }
    };
    if locked_db.contains_key(acct.account_name.as_str()) {
        return (
            Status::NotAcceptable,
            Json(RegResponse {
                account_name: String::from(&acct.account_name),
                nonce: 0,
                message: String::from("Already Exists"),
            }),
        );
    }
    locked_db.insert(String::from(&acct.account_name), v);
    let nonce = locked_db.get(&acct.account_name).unwrap().nonce();

    (
        Status::Accepted,
        Json(RegResponse {
            account_name: String::from(&acct.account_name),
            nonce: *nonce,
            message: String::from(""),
        }),
    )
}

#[post("/message", format = "json", data = "<msg>")]
fn message(db: &State<InMemDB>, msg: Json<SignedMessage>) -> (Status, Json<RegResponse>) {
    let mut locked_db = db.db.lock().unwrap();
    if !locked_db.contains_key(msg.account_name.as_str()) {
        return (
            Status::NotFound,
            Json(RegResponse {
                account_name: String::from(&msg.account_name),
                nonce: 0,
                message: String::from("Account not found"),
            }),
        );
    }

    let acct = locked_db.get_mut(&msg.account_name).unwrap();
    if !acct.verify_nonce(&msg.nonce) {
        (*acct).new_nonce();
        return (
            Status::NotAcceptable,
            Json(RegResponse {
                account_name: String::from(&msg.account_name),
                nonce: *acct.nonce(),
                message: String::from("Invalid Nonce"),
            }),
        );
    }
    (*acct).new_nonce();
    match acct.verify_message(&msg.message, &msg.digest.as_str()) {
        Ok(()) => (),
        Err(e) => {
            return (
                Status::NotAcceptable,
                Json(RegResponse {
                    account_name: String::from(&msg.account_name),
                    nonce: *acct.nonce(),
                    message: String::from(e.message),
                }),
            )
        }
    }

    (
        Status::Accepted,
        Json(RegResponse {
            account_name: String::from(""),
            nonce: *acct.nonce(),
            message: String::from("ACK"),
        }),
    )
}
#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index, register_user, message])
        .manage(InMemDB::new())
}
