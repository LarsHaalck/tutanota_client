// Copyright 2019 Fredrik Portström <https://portstrom.com>
// This is free software distributed under the terms specified in
// the file LICENSE at the top-level directory of this distribution.

use super::Error;
use futures::Future;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Mail {
    #[serde(with = "super::protocol::format")]
    _format: (),
    pub attachments: Vec<(String, String)>,
    pub body: String,
    #[serde(rename = "_id")]
    pub id: (String, String),
    #[serde(with = "super::protocol::base64", rename = "_ownerEncSessionKey")]
    pub owner_enc_session_key: Vec<u8>,
    #[serde(rename = "receivedDate")]
    pub received_date: String,
    #[serde(rename = "sentDate")]
    pub sent_date: String,
    pub sender: Sender,
    #[serde(with = "super::protocol::base64")]
    pub subject: Vec<u8>,
    pub unread: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Sender {
    pub address: String,
    #[serde(with = "super::protocol::base64")]
    pub name: Vec<u8>,
}

pub fn fetch_mail<C: 'static + hyper::client::connect::Connect>(
    client: &hyper::Client<C, hyper::Body>,
    access_token: &str,
    mails: &str,
) -> impl futures::Future<Error = Error, Item = Vec<Mail>> {
    let url = format!(
        "https://mail.tutanota.com/rest/tutanota/mail/{}?start=zzzzzzzzzzzz&count=100&reverse=true",
        mails
    );
    super::authenticated_get::get(client, access_token, &url).and_then(|response_body| {
        serde_json::from_slice::<Vec<Mail>>(&response_body).map_err(Error::Format)
    })
}
