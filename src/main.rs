use digital_signature::{
    database::{AccountInfo, InMemDB},
    request::Acct,
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

#[post("/message")]
fn message(db: &State<InMemDB>) -> &'static str {
    let mut locked_db = db.db.lock().unwrap();

    "register user"
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
