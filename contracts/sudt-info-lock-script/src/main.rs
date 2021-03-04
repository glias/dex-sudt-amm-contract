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

use share::ckb_std;
use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    default_alloc,
    high_level::{load_cell, load_script, QueryIter},
};

use share::{blake2b, get_cell_type_hash};

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
    let group_count = QueryIter::new(load_cell, Source::GroupInput).count();
    let info_type_hash = get_cell_type_hash!(0, Source::GroupInput);
    let pool_x_type_hash = get_cell_type_hash!(1, Source::GroupInput);
    let self_args: Vec<u8> = load_script()?.args().unpack();

    match group_count {
        2 => {
            // CKB <-> SUDT
            if blake2b!("ckb", pool_x_type_hash) != self_args[0..32] {
                return Err(Error::PoolTypeHashMismatch);
            }

            if info_type_hash != self_args[32..64] {
                return Err(Error::InfoTypeHashMismatch);
            }
        }

        3 => {
            // SUDT <-> CKB
            let pool_y_type_hash = get_cell_type_hash!(2, Source::GroupInput);
            if blake2b!(pool_x_type_hash, pool_y_type_hash) != self_args[0..32] {
                return Err(Error::PoolTypeHashMismatch);
            }

            if info_type_hash != self_args[32..64] {
                return Err(Error::InfoTypeHashMismatch);
            }
        }

        _ => return Err(Error::InvalidInfoCellCount),
    }

    Ok(())
}
