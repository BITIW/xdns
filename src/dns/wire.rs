use std::collections::BTreeSet;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

pub fn query_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([packet[0], packet[1]]))
}

pub fn question_name(query: &[u8]) -> Option<String> {
    let message = Message::from_vec(query).ok()?;
    let question = message.queries().first()?;
    Some(question.name().to_utf8())
}

pub fn normalize_domain(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub fn response_names(response: &[u8]) -> Vec<String> {
    let Ok(message) = Message::from_vec(response) else {
        return Vec::new();
    };

    let mut names = BTreeSet::new();
    for record in message
        .answers()
        .iter()
        .chain(message.name_servers().iter())
        .chain(message.additionals().iter())
    {
        names.insert(normalize_domain(&record.name().to_utf8()));
    }

    names.into_iter().collect()
}

pub fn set_query_id(packet: &mut [u8], id: u16) {
    if packet.len() < 2 {
        return;
    }
    let bytes = id.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
}

pub fn cache_key(query: &[u8]) -> Vec<u8> {
    let mut key = query.to_vec();
    if key.len() >= 2 {
        key[0] = 0;
        key[1] = 0;
    }
    key
}

pub fn is_negative_response(response: &[u8]) -> bool {
    let Ok(message) = Message::from_vec(response) else {
        return false;
    };

    message.response_code() != ResponseCode::NoError || message.answers().is_empty()
}

pub fn min_ttl(response: &[u8]) -> Option<u32> {
    let message = Message::from_vec(response).ok()?;

    message
        .answers()
        .iter()
        .chain(message.name_servers().iter())
        .chain(message.additionals().iter())
        .map(|record| record.ttl())
        .min()
}

pub fn is_truncated(response: &[u8]) -> bool {
    response.len() >= 4 && (response[2] & 0b0000_0010) != 0
}

pub fn build_servfail_response(query: &[u8]) -> Vec<u8> {
    if let Ok(query_message) = Message::from_vec(query) {
        let mut response = Message::new();
        response.set_id(query_message.id());
        response.set_op_code(query_message.op_code());
        response.set_message_type(MessageType::Response);
        response.set_recursion_desired(query_message.recursion_desired());
        response.set_response_code(ResponseCode::ServFail);

        for question in query_message.queries() {
            response.add_query(question.clone());
        }

        let mut out = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut out);
        if response.emit(&mut encoder).is_ok() {
            return out;
        }
    }

    // Fallback minimal SERVFAIL, preserving question count and body as-is.
    let mut response = query.to_vec();
    if response.len() < 12 {
        return Vec::new();
    }
    response[2] = (response[2] & 0b0111_1001) | 0b1000_0000;
    response[3] = 0b0000_0010;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    response
}
