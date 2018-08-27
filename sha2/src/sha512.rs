use block_buffer::BlockBuffer1024;
use byte_tools::{write_u32_be, write_u64v_be};
use digest;
use digest::generic_array::typenum::{U128, U28, U32, U48, U64};
use digest::generic_array::GenericArray;

use consts::{H384, H512, H512_TRUNC_224, H512_TRUNC_256, STATE_LEN};

#[cfg(feature = "asm")]
use sha2_asm::compress512;
#[cfg(not(feature = "asm"))]
use sha512_utils::compress512;
use sha512_utils::compress512_with_salt;

type BlockSize = U128;
pub type Block = [u8; 128];

/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Clone)]
struct Engine512State {
    h: [u64; 8],
}

impl Engine512State {
    fn new(h: &[u64; 8]) -> Engine512State {
        Engine512State { h: *h }
    }

    pub fn process_block(&mut self, data: &Block) {
        compress512(&mut self.h, data);
    }

    pub fn process_block_with_salt(&mut self, data: &Block, salt: &[u8]) {
        compress512_with_salt(&mut self.h, data, salt);
    }
}

/// A structure that keeps track of the state of the Sha-512 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone)]
struct Engine512 {
    len: (u64, u64), // TODO: replace with u128 on stabilization
    buffer: BlockBuffer1024,
    state: Engine512State,
}

impl Engine512 {
    fn new(h: &[u64; STATE_LEN]) -> Engine512 {
        Engine512 {
            len: (0, 0),
            buffer: Default::default(),
            state: Engine512State::new(h),
        }
    }

    fn input(&mut self, input: &[u8]) {
        let (res, over) = self.len.1.overflowing_add((input.len() as u64) << 3);
        self.len.1 = res;
        if over {
            self.len.0 += 1;
        }
        let self_state = &mut self.state;
        self.buffer.input(input, |d| self_state.process_block(d));
    }

    fn finish(&mut self) {
        let self_state = &mut self.state;
        let (mut hi, mut lo) = self.len;
        // TODO: change `len_padding_u128` to use BE
        if cfg!(target_endian = "little") {
            hi = hi.to_be();
            lo = lo.to_be();
        } else {
            hi = hi.to_le();
            lo = lo.to_le();
        };
        self.buffer
            .len_padding_u128(hi, lo, |d| self_state.process_block(d));
    }

    fn input_with_salt(&mut self, input: &[u8], salt: &[u8]) {
        let (res, over) = self.len.1.overflowing_add((input.len() as u64) << 3);
        self.len.1 = res;
        if over {
            self.len.0 += 1;
        }
        let self_state = &mut self.state;
        self.buffer
            .input(input, |d| self_state.process_block_with_salt(d, salt));
    }

    fn finish_with_salt(&mut self, salt: &[u8]) {
        let self_state = &mut self.state;
        let (mut hi, mut lo) = self.len;
        // TODO: change `len_padding_u128` to use BE
        if cfg!(target_endian = "little") {
            hi = hi.to_be();
            lo = lo.to_be();
        } else {
            hi = hi.to_le();
            lo = lo.to_le();
        };
        self.buffer
            .len_padding_u128(hi, lo, |d| self_state.process_block_with_salt(d, salt));
    }
}

/// The SHA-512 hash algorithm with the SHA-512 initial hash value.
#[derive(Clone)]
pub struct Sha512 {
    engine: Engine512,
}

impl Default for Sha512 {
    fn default() -> Self {
        Sha512 {
            engine: Engine512::new(&H512),
        }
    }
}

impl digest::BlockInput for Sha512 {
    type BlockSize = BlockSize;
}

impl digest::Input for Sha512 {
    fn process(&mut self, msg: &[u8]) {
        self.engine.input(msg);
    }
}

impl digest::FixedOutput for Sha512 {
    type OutputSize = U64;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::default();
        write_u64v_be(out.as_mut_slice(), &self.engine.state.h[..]);
        out
    }
}

/// The SHA-512 hash algorithm with the SHA-512 initial hash value.
#[derive(Clone)]
pub struct Sha512_salted {
    engine: Engine512,
    salt: [u8; 128],
}

impl Sha512_salted {
    pub fn input(&mut self, msg: &[u8]) {
        self.engine.input_with_salt(msg, &self.salt);
    }

    pub fn result(mut self) -> GenericArray<u8, U64> {
        self.engine.finish_with_salt(&self.salt);

        let mut out = GenericArray::default();
        write_u64v_be(out.as_mut_slice(), &self.engine.state.h[..]);
        out
    }
}

pub fn default_sha512_salted(salt: &[u8]) -> Sha512_salted {
    let mut salt_local = [0u8; 128];
    assert!(salt.len() == 128);
    salt_local.copy_from_slice(salt);

    Sha512_salted {
        engine: Engine512::new(&H512),
        salt: salt_local,
    }
}

/// The SHA-512 hash algorithm with the SHA-384 initial hash value. The result
/// is truncated to 384 bits.
#[derive(Clone)]
pub struct Sha384 {
    engine: Engine512,
}

impl Default for Sha384 {
    fn default() -> Self {
        Sha384 {
            engine: Engine512::new(&H384),
        }
    }
}

impl digest::BlockInput for Sha384 {
    type BlockSize = BlockSize;
}

impl digest::Input for Sha384 {
    fn process(&mut self, msg: &[u8]) {
        self.engine.input(msg);
    }
}

impl digest::FixedOutput for Sha384 {
    type OutputSize = U48;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::default();
        write_u64v_be(out.as_mut_slice(), &self.engine.state.h[..6]);
        out
    }
}

/// The SHA-512 hash algorithm with the SHA-512/256 initial hash value. The
/// result is truncated to 256 bits.
#[derive(Clone)]
pub struct Sha512Trunc256 {
    engine: Engine512,
}

impl Default for Sha512Trunc256 {
    fn default() -> Self {
        Sha512Trunc256 {
            engine: Engine512::new(&H512_TRUNC_256),
        }
    }
}

impl digest::BlockInput for Sha512Trunc256 {
    type BlockSize = BlockSize;
}

impl digest::Input for Sha512Trunc256 {
    fn process(&mut self, msg: &[u8]) {
        self.engine.input(msg);
    }
}

impl digest::FixedOutput for Sha512Trunc256 {
    type OutputSize = U32;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::default();
        write_u64v_be(out.as_mut_slice(), &self.engine.state.h[..4]);
        out
    }
}

/// The SHA-512 hash algorithm with the SHA-512/224 initial hash value.
/// The result is truncated to 224 bits.
#[derive(Clone)]
pub struct Sha512Trunc224 {
    engine: Engine512,
}

impl Default for Sha512Trunc224 {
    fn default() -> Self {
        Sha512Trunc224 {
            engine: Engine512::new(&H512_TRUNC_224),
        }
    }
}

impl digest::BlockInput for Sha512Trunc224 {
    type BlockSize = BlockSize;
}

impl digest::Input for Sha512Trunc224 {
    fn process(&mut self, msg: &[u8]) {
        self.engine.input(msg);
    }
}

impl digest::FixedOutput for Sha512Trunc224 {
    type OutputSize = U28;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::default();
        write_u64v_be(&mut out[..24], &self.engine.state.h[..3]);
        write_u32_be(&mut out[24..28], (self.engine.state.h[3] >> 32) as u32);
        out
    }
}

impl_opaque_debug!(Sha384);
impl_opaque_debug!(Sha512);
impl_opaque_debug!(Sha512Trunc224);
impl_opaque_debug!(Sha512Trunc256);
