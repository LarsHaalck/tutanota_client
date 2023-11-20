// Copyright 2019 Fredrik Portström <https://portstrom.com>
// This is free software distributed under the terms specified in
// the file LICENSE at the top-level directory of this distribution.

use futures::{
    future::{self, Either},
    Future, Stream,
};

enum Operation {
    ViewMail,
}

use lz4_flex::block::decompress_into;

fn main() {
    let mut arguments = std::env::args();
    let program = arguments.next().unwrap();
    let quit = || {
        eprintln!(
            "Usage: {} email_address view_mail",
            program
        );
        std::process::exit(1);
    };
    if arguments.len() != 2 {
        quit();
    }
    let email_address = arguments.next().unwrap();
    let operation = match &arguments.next().unwrap() as _ {
        "view_mail" => Operation::ViewMail,
        _ => quit(),
    };
    let password = rpassword::prompt_password_stderr("Password: ").unwrap_or_else(|error| {
        eprintln!("Failed to read password: {}", error);
        std::process::exit(1);
    });
    hyper::rt::run(hyper::rt::lazy(|| {
        let https = hyper_tls::HttpsConnector::new(4).unwrap();
        let client = hyper::Client::builder().build::<_, hyper::Body>(https);
        tutanota_client::salt::fetch_salt(&client, &email_address)
            .and_then(move |salt| {
                let user_passphrase_key =
                    tutanota_client::create_user_passphrase_key(&password, &salt);
                tutanota_client::session::fetch_session(
                    &client,
                    "Rust",
                    &email_address,
                    &user_passphrase_key,
                )
                .and_then(move |response| {
                    let access_token = response.access_token;
                    tutanota_client::user::fetch_user(&client, &access_token, &response.user)
                        .and_then(move |response| {
                            // XXX avoid panic
                            let membership = response
                                .memberships
                                .iter()
                                .find(|membership| membership.group_type == "5")
                                .unwrap();
                            // XXX avoid panic
                            let user_group_key = tutanota_client::decrypt_key(
                                &user_passphrase_key,
                                &response.user_group.sym_enc_g_key,
                            )
                            .unwrap();
                            // XXX avoid panic
                            let mail_group_key = tutanota_client::decrypt_key(
                                &user_group_key,
                                &membership.sym_enc_g_key,
                            )
                            .unwrap();
                            tutanota_client::mailboxgrouproot::fetch_mailboxgrouproot(
                                &client,
                                &access_token,
                                &membership.group,
                            )
                            .and_then(move |mailbox| {
                                tutanota_client::mailbox::fetch_mailbox(
                                    &client,
                                    &access_token,
                                    &mailbox,
                                )
                                .and_then(move |folders| {
                                    tutanota_client::mailfolder::fetch_mailfolder(
                                        &client,
                                        &access_token,
                                        &folders,
                                    )
                                    .and_then(move |folders| -> Box<dyn Future<Error = _, Item = _> + Send> {
                                        // XXX avoid panic
                                        match operation {
                                            Operation::ViewMail => Box::new(fetch_mails(client, access_token, mail_group_key, &folders[0].mails)),
                                        }
                                    })
                                })
                            })
                        })
                })
            })
            .or_else(|error| {
                eprintln!("Error: {:#?}", error);
                match error {
                    tutanota_client::Error::ContentType(response)
                    | tutanota_client::Error::Status(response) => {
                        Either::A(response.into_body().concat2().then(|result| {
                            match result {
                                Err(error) => eprintln!("Network error: {}", error),
                                Ok(response_body) => {
                                    eprintln!(
                                        "Response body: {:?}",
                                        std::str::from_utf8(&response_body)
                                    );
                                }
                            }
                            Ok(())
                        }))
                    }
                    _ => Either::B(future::ok(())),
                }
            })
    }));
}

fn fetch_mails<C: 'static + hyper::client::connect::Connect>(
    client: hyper::Client<C, hyper::Body>,
    access_token: String,
    mail_group_key: [u8; 16],
    mails: &str,
) -> impl Future<Error = tutanota_client::Error, Item = ()> {
    tutanota_client::mail::fetch_mail(&client, &access_token, mails).and_then(move |mails| {
        for mail in &mails {
            // XXX avoid panic
            let session_key =
                tutanota_client::decrypt_key(&mail_group_key, &mail.owner_enc_session_key).unwrap();
            let session_sub_keys = tutanota_client::SubKeys::new(session_key);
            // XXX avoid panic
            let title =
                tutanota_client::decrypt_with_mac(&session_sub_keys, &mail.subject).unwrap();
            // XXX avoid panic
            println!(
                "mail, subject: {:?}, from: {:?}",
                std::str::from_utf8(&title).unwrap(),
                mail.sender.address,
            );
        }
        // XXX avoid panic
        let mail = mails.into_iter().next().unwrap();
        fetch_mail_contents(client, access_token, mail_group_key, mail)
    })
}

fn fetch_mail_contents<C: 'static + hyper::client::connect::Connect>(
    client: hyper::Client<C, hyper::Body>,
    access_token: String,
    mail_group_key: [u8; 16],
    mail: tutanota_client::mail::Mail,
) -> impl Future<Error = tutanota_client::Error, Item = ()> {
    println!("Num attachments: {}", mail.attachments.len());
    let mailbody_future =
        tutanota_client::mailbody::fetch_mailbody(&client, &access_token, &mail.body);
    let session_key = tutanota_client::decrypt_key(&mail_group_key, &mail.owner_enc_session_key).unwrap();
    let session_sub_keys = tutanota_client::SubKeys::new(session_key);
    mailbody_future
        .map(move |text| {
            // XXX avoid panic
            let compressed_text = tutanota_client::decrypt_with_mac(&session_sub_keys, &text).unwrap();

            let mut buf : Vec<u8> = vec![0; text.len() * 6];
            let size = decompress_into(&compressed_text, &mut buf).unwrap();
            buf.resize(size, 0);

            // XXX avoid panic
            println!("mail body: {}", std::str::from_utf8(&buf).unwrap());
        })
}
