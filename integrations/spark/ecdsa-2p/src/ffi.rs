//! Declarations for the subset of cb-mpc's public C API used here
//! (`cbmpc/c_api/{cmem,common,job,ecdsa_2p}.h` at the pinned commit, plus the
//! blind entry point from the in-repo patch).
use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
pub struct Cmem {
    pub data: *mut u8,
    pub size: c_int,
}

impl Cmem {
    pub const EMPTY: Self = Self {
        data: std::ptr::null_mut(),
        size: 0,
    };

    /// Borrowed input; the library never takes ownership of input buffers.
    pub fn view(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr().cast_mut(),
            size: bytes.len() as c_int,
        }
    }
}

pub type SendFn = unsafe extern "C" fn(*mut c_void, i32, *const u8, c_int) -> c_int;
pub type ReceiveFn = unsafe extern "C" fn(*mut c_void, i32, *mut Cmem) -> c_int;

#[repr(C)]
pub struct Transport {
    pub ctx: *mut c_void,
    pub send: SendFn,
    pub receive: ReceiveFn,
    pub receive_all: *const c_void,
    /// Null: the library releases received buffers with `cbmpc_free`.
    pub free: *const c_void,
}

#[repr(C)]
pub struct Job2p {
    pub party: c_int,
    pub p1_name: *const c_char,
    pub p2_name: *const c_char,
    pub transport: *const Transport,
}

pub const SUCCESS: c_int = 0;
pub const NETWORK_ERROR: c_int = 0xff03_0001_u32 as c_int;
pub const SECP256K1: c_int = 2;

unsafe extern "C" {
    pub fn cbmpc_malloc(size: usize) -> *mut c_void;
    pub fn cbmpc_cmem_free(mem: Cmem);
    pub fn cbmpc_ecdsa_2p_dkg(job: *const Job2p, curve: c_int, out: *mut Cmem) -> c_int;
    pub fn cbmpc_ecdsa_2p_sign(
        job: *const Job2p,
        key: Cmem,
        msg_hash: Cmem,
        sid_in: Cmem,
        sid_out: *mut Cmem,
        sig_der: *mut Cmem,
    ) -> c_int;
    /// Added by `scripts/cbmpc-blind-sign.patch`.
    pub fn cbmpc_ecdsa_2p_sign_blind(
        job: *const Job2p,
        key: Cmem,
        msg_hash: Cmem,
        tau: Cmem,
        sid_in: Cmem,
        sid_out: *mut Cmem,
        sig_der: *mut Cmem,
    ) -> c_int;
    pub fn cbmpc_ecdsa_2p_get_public_key_compressed(key: Cmem, out: *mut Cmem) -> c_int;
    pub fn cbmpc_ecdsa_2p_get_public_share_compressed(key: Cmem, out: *mut Cmem) -> c_int;
    pub fn cbmpc_ecdsa_2p_detach_private_scalar(
        key: Cmem,
        out_detached: *mut Cmem,
        out_scalar: *mut Cmem,
    ) -> c_int;
}
