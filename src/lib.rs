#![feature(trait_alias)]

pub mod config;
pub mod error;
pub mod secret_key;
pub mod word_config;

// This function should return a cipher text for a given key and plaintext
//
pub fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
  let mut ciphertext = Vec::new();
  ciphertext
}

// This function should return a plaintext for a given key and ciphertext
//
pub fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
  let mut plaintext = Vec::new();
  plaintext
}
