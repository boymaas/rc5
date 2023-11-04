use rc5::{decode, encode, Rc5_128, Rc5_16, Rc5_32, Rc5_64, Rc5_8};

// RC5 Test Vectors
//
// This section contains hexadecimal representations of key and block
// inputs and the corresponding block outputs for RC5 with various word
// sizes, numbers of rounds and key bytes.
//
// https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4

// RC5-8/12/4
// Key:          00010203
// Block input:  0001
// Block output: 212A
#[test]
fn test_rc5_8_12_4() {
  let key = vec![0x00, 0x01, 0x02, 0x03];
  let pt = vec![0x00, 0x01];
  let ct = vec![0x21, 0x2A];

  let res = encode::<Rc5_8>(12, 4, &key, &pt).unwrap();
  assert!(&ct[..] == &res[..]);

  let res = decode::<Rc5_8>(12, 4, &key, &ct).unwrap();
  assert!(&pt[..] == &res[..]);
}

// RC5-16/16/8
// Key:          0001020304050607
// Block input:  00010203
// Block output: 23A8D72E
#[test]
fn test_rc5_16_16_8() {
  let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
  let pt = vec![0x00, 0x01, 0x02, 0x03];
  let ct = vec![0x23, 0xA8, 0xD7, 0x2E];

  let res = encode::<Rc5_16>(16, 8, &key, &pt).unwrap();
  assert!(&ct[..] == &res[..]);

  let res = decode::<Rc5_16>(16, 8, &key, &ct).unwrap();
  assert!(&pt[..] == &res[..]);
}

// RC5-32/20/16
// Key:          000102030405060708090A0B0C0D0E0F
// Block input:  0001020304050607
// Block output: 2A0EDC0E9431FF73
#[test]
fn test_rc5_32_20_16() {
  let key = vec![
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  ];
  let pt = vec![
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, //
    0x06, 0x07,
  ];
  let ct = vec![
    0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, //
    0xFF, 0x73,
  ];

  let res = encode::<Rc5_32>(20, 16, &key, &pt).unwrap();
  assert!(&ct[..] == &res[..]);

  let res = decode::<Rc5_32>(20, 16, &key, &ct).unwrap();
  assert!(&pt[..] == &res[..]);
}

// RC5-64/24/24
// Key:          000102030405060708090A0B0C0D0E0F1011121314151617
// Block input:  000102030405060708090A0B0C0D0E0F
// Block output: A46772820EDBCE0235ABEA32AE7178DA
#[test]
fn test_rc5_64_24_24() {
  let key = vec![
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, //
    0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, //
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, //
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  ];
  let pt = vec![
    0x00, 0x01, 0x02, 0x03, //
    0x04, 0x05, 0x06, 0x07, //
    0x08, 0x09, 0x0A, 0x0B, //
    0x0C, 0x0D, 0x0E, 0x0F,
  ];
  let ct = vec![
    0xA4, 0x67, 0x72, 0x82, //
    0x0E, 0xDB, 0xCE, 0x02, //
    0x35, 0xAB, 0xEA, 0x32, //
    0xAE, 0x71, 0x78, 0xDA,
  ];

  let res = encode::<Rc5_64>(24, 24, &key, &pt).unwrap();
  assert!(&ct[..] == &res[..]);

  let res = decode::<Rc5_64>(24, 24, &key, &ct).unwrap();
  assert!(&pt[..] == &res[..]);
}

// RC5-128/28/32
// Key:          000102030405060708090A0B0C0D0E0F
//               101112131415161718191A1B1C1D1E1F
// Block input:  000102030405060708090A0B0C0D0E0F
//               101112131415161718191A1B1C1D1E1F
// Block output: ECA5910921A4F4CFDD7AD7AD20A1FCBA
//               068EC7A7CD752D68FE914B7FE180B440
#[test]
fn test_rc5_128_28_32() {
  let key = vec![
    0x00, 0x01, 0x02, 0x03, //
    0x04, 0x05, 0x06, 0x07, //
    0x08, 0x09, 0x0A, 0x0B, //
    0x0C, 0x0D, 0x0E, 0x0F, //
    0x10, 0x11, 0x12, 0x13, //
    0x14, 0x15, 0x16, 0x17, //
    0x18, 0x19, 0x1A, 0x1B, //
    0x1C, 0x1D, 0x1E, 0x1F,
  ];
  let pt = vec![
    0x00, 0x01, 0x02, 0x03, //
    0x04, 0x05, 0x06, 0x07, //
    0x08, 0x09, 0x0A, 0x0B, //
    0x0C, 0x0D, 0x0E, 0x0F, //
    0x10, 0x11, 0x12, 0x13, //
    0x14, 0x15, 0x16, 0x17, //
    0x18, 0x19, 0x1A, 0x1B, //
    0x1C, 0x1D, 0x1E, 0x1F,
  ];

  let ct = [
    0xEC, 0xA5, 0x91, 0x09, 0x21, 0xA4, 0xF4, 0xCF, 0xDD, 0x7A, 0xD7, 0xAD,
    0x20, 0xA1, 0xFC, 0xBA, 0x06, 0x8E, 0xC7, 0xA7, 0xCD, 0x75, 0x2D, 0x68,
    0xFE, 0x91, 0x4B, 0x7F, 0xE1, 0x80, 0xB4, 0x40,
  ];

  let res = encode::<Rc5_128>(28, 32, &key, &pt).unwrap();
  assert!(&ct[..] == &res[..]);

  let res = decode::<Rc5_128>(28, 32, &key, &ct).unwrap();
  assert!(&pt[..] == &res[..]);
}

// W NOT POWER OF TWO NOT SUPPORTED

// RC5-24/4/0 (non-standard, w not power of two)
// Key:
// Block input:  000102030405
// Block output: 89CBDCC9525A

// RC5-80/4/12 (non-standard, w not power of two)
// Key:          000102030405060708090A0B
// Block input:  000102030405060708090A0B0C0D0E0F10111213
// Block output: 9CB59ECBA4EA84568A4278B0E132D5FC9D5819D6
