//! Generated by capsule
//!
//! `main.rs` is used to define rust lang items and modules.
//! See `entry.rs` for the `main` function.
//! See `error.rs` for the `Error` type.

#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

mod error;

use alloc::vec::Vec;
use core::result::Result;

use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    debug, default_alloc,
    high_level::{load_cell_lock_hash, load_script, load_witness_args, QueryIter},
};
use share::{ckb_std, get_cell_type_hash};

use error::Error;

default_alloc!(4 * 1024, 2048 * 1024, 64);

ckb_std::entry!(program_entry);

/// program entry
fn program_entry() -> i8 {
    // Call main function and return error code
    match main() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

fn main() -> Result<(), Error> {
    let self_args: Vec<u8> = load_script()?.args().unpack();

    // Cancel request
    for (idx, lock_hash) in QueryIter::new(load_cell_lock_hash, Source::Input).enumerate() {
        if lock_hash == self_args[32..64]
            && load_witness_args(idx, Source::Input)?.total_size() != 0
        {
            return Ok(());
        }
    }

    if get_cell_type_hash!(0, Source::Input) == self_args[0..32] {
        return Ok(());
    }

    Err(Error::CancelFailed)
}
