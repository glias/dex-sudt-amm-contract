use alloc::vec::Vec;

use num_bigint::BigUint;
use share::cell::SwapRequestLockArgs;
use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    high_level::{load_cell, load_cell_data},
};
use share::{decode_u128, get_cell_type_hash};

use crate::entry::utils::{verify_ckb_cell, verify_sudt_basic};
use crate::entry::{
    BASE_CELL_COUNT, FEE_RATE, MIN_SUDT_CAPACITY, ONE, SUDT_DATA_LEN, THOUSAND, VERSION,
};
use crate::error::Error;

pub fn swap_tx_verification(
    swap_cell_count: usize,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    pool_x_type_hash: [u8; 32],
    pool_y_type_hash: [u8; 32],
) -> Result<(), Error> {
    for rlt_idx in 0..swap_cell_count {
        let req_index = BASE_CELL_COUNT + rlt_idx;
        let sudt_index = BASE_CELL_COUNT + rlt_idx * 2;
        let ckb_index = sudt_index + 1;

        let req_cell = load_cell(req_index, Source::Input)?;
        let raw_lock_args: Vec<u8> = req_cell.lock().args().unpack();
        let req_lock_args = SwapRequestLockArgs::from_raw(&raw_lock_args)?;
        let req_type_hash = get_cell_type_hash!(req_index, Source::Input);
        let user_lock_hash = req_lock_args.user_lock_hash;

        if req_lock_args.version != VERSION {
            return Err(Error::VersionDiff);
        }

        let sudt_out_cell = load_cell(sudt_index, Source::Output)?;
        let sudt_out_type_hash = get_cell_type_hash!(sudt_index, Source::Output);
        let sudt_out_data = load_cell_data(sudt_index, Source::Output)?;

        // req.type_hash == pool_x.type_hash == pool_y.type_hash
        if req_type_hash != pool_x_type_hash && req_type_hash != pool_y_type_hash {
            return Err(Error::InvalidSwapReqTypeHash);
        }

        // req.data.len >= 16
        if load_cell_data(req_index, Source::Input)?.len() < SUDT_DATA_LEN {
            return Err(Error::InvalidSwapReqDataLen);
        }

        if req_lock_args.sudt_type_hash != pool_x_type_hash
            && req_lock_args.sudt_type_hash != pool_y_type_hash
        {
            return Err(Error::InvalidSwapReqLockArgsTypeHash);
        }

        // swap self
        if req_type_hash == sudt_out_type_hash {
            return Err(Error::InvalidSUDTOutTypeHash);
        }

        verify_sudt_basic(sudt_index, &sudt_out_cell, &sudt_out_data, user_lock_hash)?;

        if sudt_out_type_hash != req_lock_args.sudt_type_hash {
            return Err(Error::InvalidSUDTOutTypeHash);
        }

        let expected_ckb_capcatiy =
            (req_cell.capacity().unpack() - MIN_SUDT_CAPACITY - req_lock_args.tips_ckb) as u128;

        verify_ckb_cell(
            ckb_index,
            Source::Output,
            expected_ckb_capcatiy,
            user_lock_hash,
        )?;

        let amount_in =
            decode_u128(&load_cell_data(req_index, Source::Input)?)? - req_lock_args.tips_sudt;
        let amount_out = decode_u128(&sudt_out_data)?;

        if req_lock_args.min_amount_out == 0 || amount_out < req_lock_args.min_amount_out {
            return Err(Error::InvalidSwapReqLockArgsMinAmount);
        }

        if sudt_out_type_hash == pool_y_type_hash {
            // SUDT_X => SUDT_Y
            x_exchange_y(amount_in, amount_out, sudt_x_reserve, sudt_y_reserve)?;
        } else {
            // SUDT_Y => SUDT_X
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
