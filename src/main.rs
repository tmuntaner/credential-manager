use structopt::StructOpt;

pub mod aws;
pub mod okta;
pub mod verify;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(StructOpt, Debug)]
#[structopt(name = "credman")]
struct Opt {}

#[tokio::main]
async fn main() -> Result<()> {
    let _opt = Opt::from_args();
    let service = "credman";
    let username = "tmuntaner@suse.com";

    let keyring = keyring::Keyring::new(service, username);
    let password = keyring.get_password().unwrap();

    let state_machine = okta::state_machine::Factory {};
    state_machine
        .run(
            String::from(username),
            password,
            String::from("https://suse.okta.com"),
        )
        .await
        .unwrap();

    //let client = OktaClient::new().unwrap();
    //client.authorize(username.to_string(), password).await?;

    Ok(())
}
