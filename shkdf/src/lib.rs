// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]

extern crate orion;
extern crate rand;
extern crate sha2;

#[cfg(test)]
pub mod tests;

use orion::hazardous::hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{default_sha512_salted, Sha512_salted};

pub struct HmacSha512 {
    buffer: [u8; 128],
    salt: [u8; 128],
    hasher: Sha512_salted,
    is_finalized: bool,
}

impl HmacSha512 {
    /// Pad key and construct inner-padding
    fn pad_key_to_ipad(&mut self, key: &[u8]) {
        if key.len() > 128 {
            let mut hasher = default_sha512_salted(&self.salt);
            hasher.input(&key);
            self.buffer[..64].copy_from_slice(&hasher.result());

            for itm in self.buffer.iter_mut().take(64) {
                *itm ^= 0x36;
            }
        } else {
            for idx in 0..key.len() {
                self.buffer[idx] ^= key[idx];
            }
        }

        self.hasher.input(&self.buffer);
    }
    /// Call the core finalization steps.
    fn core_finalize(&mut self, hash_ores: &mut Sha512_salted) {
        if self.is_finalized {
            panic!("Unable to call finalize twice without reset");
        }

        self.is_finalized = true;

        let mut hash_ires = default_sha512_salted(&self.salt);
        core::mem::swap(&mut self.hasher, &mut hash_ires);

        for idx in self.buffer.iter_mut() {
            // XOR with the result of XOR(0x36 ^ 0x5C)
            // Which is equivalent of inverting the ipad
            // and then constructing the opad
            *idx ^= 0x6A;
        }

        hash_ores.input(&self.buffer);
        hash_ores.input(&hash_ires.result());
    }

    /// This can be called multiple times for streaming messages.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.input(message);
    }
    /// Retrieve MAC and copy into `dst`.
    pub fn finalize_with_dst(&mut self, dst: &mut [u8]) {
        let mut hash_ores = default_sha512_salted(&self.salt);
        self.core_finalize(&mut hash_ores);
        let dst_len = dst.len();

        dst.copy_from_slice(&hash_ores.result()[..dst_len]);
    }
}

/// Initialize HmacSha512 struct with a given key, for use with streaming messages.
pub fn init(secret_key: &[u8], salt: &[u8]) -> HmacSha512 {
    assert!(salt.len() == 128);
    let mut checked_salt = [0u8; 128];
    checked_salt.copy_from_slice(salt);

    let mut mac = HmacSha512 {
        // Initialize to 128 * (0x00 ^ 0x36) so that
        // we can later xor the rest of the key in-place
        buffer: [0x36; 128],
        salt: checked_salt,
        hasher: default_sha512_salted(&salt),
        is_finalized: false,
    };

    mac.pad_key_to_ipad(secret_key);

    mac
}

pub fn gen_salt(dst: &mut [u8]) {
    assert_eq!(dst.is_empty(), false);
    let mut generator = OsRng::new().unwrap();
    generator.try_fill_bytes(dst).unwrap();
}

// Salt here is not the iteration salt
fn shkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    let mut prk = hmac::init(salt);
    prk.update(ikm);

    prk.finalize()
}

fn shkdf_expand(prk: &[u8], info: &[u8], okm_out: &mut [u8], special_salt: &[u8]) {
    if okm_out.len() > 16320 {
        panic!("Len too high");
    }
    if okm_out.is_empty() {
        panic!("okm_out cannot be empty");
    }

    let okm_len = okm_out.len();
    // Extensive length checks for the salt
    // TODO: Find some better checks instead of using floats
    let len_check = (okm_len as f32 / 64_f32) * 128_f32;
    assert!(special_salt.len() >= len_check as usize);
    assert!(special_salt.len() >= 128);
    assert!(special_salt.len() % 128 == 0);
    assert!(special_salt.len() > okm_len);
    assert_eq!(special_salt.is_empty(), false);

    let mut prev_switch = false;
    let mut prev_block = [0u8; 64]; // Can at max be 64 in length

    for (idx, hlen_block) in okm_out.chunks_mut(64).enumerate() {
        let block_len = hlen_block.len();
        assert!(block_len <= okm_len);

        let mut hmac = init(prk, &special_salt[idx * 128..(idx + 1) * 128]);
        if prev_switch {
            hmac.update(&prev_block);
        }
        hmac.update(info);
        hmac.update(&[idx as u8 + 1_u8]);
        hmac.finalize_with_dst(&mut hlen_block[..block_len]);

        // Check if it's the last iteration, if yes don't process anything
        if block_len < 64 || (block_len * (idx + 1) == okm_len) {
            break;
        } else {
            prev_block.copy_from_slice(&hlen_block[..block_len]);
            prev_switch = true;
        }
    }
}

pub fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8], okm_out: &mut [u8], special_salt: &[u8]) {
    let prk = shkdf_extract(salt, ikm);

    shkdf_expand(&prk, info, okm_out, special_salt);
}
