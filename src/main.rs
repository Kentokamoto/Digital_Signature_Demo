use digital_signature::{AccountInfo, InMemDB};
use rocket::State;

#[macro_use]
extern crate rocket;

#[get("/")]
fn index(db: &State<InMemDB>) -> &'static str {
    db.db.lock().unwrap().insert(
        String::from("Test"),
        AccountInfo::new(String::from("PUBLIC_KEY")),
    );
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
        .manage(InMemDB::new())
}
