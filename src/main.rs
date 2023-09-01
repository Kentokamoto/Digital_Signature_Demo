use digital_signature::{
    database::{AccountInfo, InMemDB},
    request::Acct,
    response::RegResponse,
};
use rocket::{serde::json::Json, State};

#[macro_use]
extern crate rocket;

#[post("/register", format = "json", data = "<acct>")]
fn register_user(db: &State<InMemDB>, acct: Json<Acct<'_>>) -> Json<RegResponse> {
    let mut locked_db = db.db.lock().unwrap();
    let v = AccountInfo::new(String::from(acct.public_key));
    locked_db.insert(String::from(acct.account_name), v);
    let a = locked_db.get(&String::from(acct.account_name)).unwrap();

    Json(RegResponse {
        account_name: String::from(acct.account_name),
        nonce: String::from(a.nonce()),
    })
}

#[post("/message")]
fn message(db: &State<InMemDB>) -> &'static str {
    db.db.lock().unwrap().insert(
        String::from("Test"),
        AccountInfo::new(String::from("PUBLIC_KEY")),
    );
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
