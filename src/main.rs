use digital_signature::{AccountInfo, InMemDB};
use rocket::{
    serde::{json::Json, Deserialize},
    State,
};

#[macro_use]
extern crate rocket;

#[post("/message")]
fn create_account(db: &State<InMemDB>) -> &'static str {
    let locked_db = db.db.lock().unwrap();
    let acct = locked_db.get("Test");
    println!("{:?}", &acct);
    "Account Created"
}

#[post("/register")]
fn register_user(db: &State<InMemDB>) -> &'static str {
    db.db.lock().unwrap().insert(
        String::from("Test"),
        AccountInfo::new(String::from("PUBLIC_KEY")),
    );
    "register user"
}
#[get("/")]
fn index(db: &State<InMemDB>) -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index, create_account])
        .manage(InMemDB::new())
}
