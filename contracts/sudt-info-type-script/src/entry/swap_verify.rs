use alloc::vec::Vec;

use num_bigint::BigUint;
use share::cell::SwapRequestLockArgs;
use share::ckb_std::ckb_types::packed::CellOutput;
use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    high_level::{load_cell, load_cell_data, load_cell_lock_hash},
};
use share::{decode_u128, get_cell_type_hash};

use crate::entry::utils::verify_ckb_cell;
use crate::entry::{FEE_RATE, MIN_SUDT_CAPACITY, ONE, THOUSAND};
use crate::error::Error;

pub fn swap_tx_verification(
    info_in_cell: &CellOutput,
    swap_cell_count: usize,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
) -> Result<(), Error> {
    // Todo: perf
    let pool_x_type_hash = get_cell_type_hash!(1, Source::Input);
    let pool_y_type_hash = get_cell_type_hash!(2, Source::Input);

    for idx in 4..(4 + swap_cell_count) {
        let req_cell = load_cell(idx, Source::Input)?;
        let raw_lock_args: Vec<u8> = req_cell.lock().args().unpack();
        let req_lock_args = SwapRequestLockArgs::from_raw(&raw_lock_args)?;
        let req_type_hash = get_cell_type_hash!(idx, Source::Input);
        let sudt_out_cell = load_cell(idx, Source::Output)?;
        let sudt_out_type_hash = get_cell_type_hash!(idx, Source::Output);

        let user_lock_hash = req_lock_args.user_lock_hash;

        if req_type_hash != pool_x_type_hash && req_type_hash != pool_y_type_hash {
            return Err(Error::InvalidSwapReqTypeHash);
        }

        if load_cell_data(idx, Source::Input)?.len() < 16 {
            return Err(Error::InvalidSwapReqDataLen);
        }

        if req_lock_args.sudt_type_hash != pool_x_type_hash
            && req_lock_args.sudt_type_hash != pool_y_type_hash
        {
            return Err(Error::InvalidSwapReqLockArgsTypeHash);
        }

        if req_type_hash == sudt_out_type_hash {
            return Err(Error::InvalidSUDTOutTypeHash);
        }

        if sudt_out_cell.capacity().unpack() != MIN_SUDT_CAPACITY {
            return Err(Error::InvalidSUDTOutCapacity);
        }

        if sudt_out_type_hash != req_lock_args.sudt_type_hash {
            return Err(Error::InvalidSUDTOutTypeHash);
        }

        if load_cell_lock_hash(idx, Source::Output)? != user_lock_hash {
            return Err(Error::InvalidSUDTOutLockHash);
        }

        verify_ckb_cell(idx + 1, Source::Output, user_lock_hash)?;

        let amount_in =
            decode_u128(&load_cell_data(idx, Source::Input)?)? - req_lock_args.tips_sudt;
        let amount_out = decode_u128(&load_cell_data(idx, Source::Output)?)?;

        if req_lock_args.min_amount_out == 0 || amount_out < req_lock_args.min_amount_out {
            return Err(Error::InvalidSwapReqLockArgsMinAmount);
        }

        if sudt_out_type_hash == pool_y_type_hash {
            // SUDT_X => SUDT_Y
            x_exchange_y(amount_in, amount_out, sudt_x_reserve, sudt_y_reserve)?;
        } else {
            y_exchange_x(amount_in, amount_out, sudt_x_reserve, sudt_y_reserve)?;
        }
    }

    Ok(())
}

fn x_exchange_y(
    amount_in: u128,
    amount_out: u128,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
) -> Result<(), Error> {
    let numerator = BigUint::from(amount_in) * FEE_RATE * (*sudt_y_reserve);
    let denominator = (*sudt_x_reserve) * THOUSAND + BigUint::from(amount_in) * FEE_RATE;

    if BigUint::from(amount_out) != numerator / denominator + ONE {
        return Err(Error::XExchangeYFailed);
    }

    *sudt_x_reserve += amount_in;
    *sudt_y_reserve -= amount_out;

    Ok(())
}

fn y_exchange_x(
    amount_in: u128,
    amount_out: u128,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
) -> Result<(), Error> {
    let numerator = BigUint::from(amount_in) * FEE_RATE * (*sudt_x_reserve);
    let denominator = (*sudt_y_reserve) * THOUSAND + FEE_RATE * BigUint::from(amount_in);

    if BigUint::from(amount_out) != numerator / denominator + ONE {
        return Err(Error::YExchangeXFailed);
    }

    *sudt_x_reserve -= amount_out;
    *sudt_y_reserve += amount_in;

    Ok(())
}
