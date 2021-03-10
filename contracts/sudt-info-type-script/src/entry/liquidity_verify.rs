use alloc::vec::Vec;
use core::convert::TryInto;
use core::result::Result;

use num_bigint::BigUint;

use share::cell::{InfoCellData, LiquidityRequestLockArgs, MintLiquidityRequestLockArgs};
use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::CellOutput, prelude::*},
    high_level::{load_cell, load_cell_data, load_cell_lock_hash},
};
use share::{decode_u128, get_cell_type_hash};

use crate::entry::utils::{verify_ckb_cell, verify_sudt_basic};
use crate::entry::{MIN_SUDT_CAPACITY, ONE};
use crate::error::Error;

pub fn liquidity_tx_verification(
    info_type_hash: [u8; 32],
    swap_cell_count: usize,
    add_liquidity_count: usize,
    input_cell_count: usize,
    info_in_data: InfoCellData,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
    pool_x_type_hash: [u8; 32],
    pool_y_type_hash: [u8; 32],
) -> Result<(), Error> {
    if *total_liquidity == 0 {
        return Err(Error::TotalLiquidityIsZero);
    }

    let add_input_base = 4 + swap_cell_count;
    let add_output_base = 4 + swap_cell_count * 2;
    let remove_input_base = 4 + swap_cell_count + add_liquidity_count * 2;
    let remove_output_base = 4 + swap_cell_count * 2 * add_liquidity_count * 3;
    let remove_count = input_cell_count - remove_input_base;

    for rlt_idx in (0..add_liquidity_count * 2).step_by(2) {
        let real_idx_input = add_input_base + rlt_idx;
        let real_idx_output = add_output_base + (rlt_idx / 2) * 3;

        mint_liquidity(
            real_idx_input,
            real_idx_output,
            info_type_hash,
            &info_in_data,
            pool_x_type_hash,
            pool_y_type_hash,
            sudt_x_reserve,
            sudt_y_reserve,
            total_liquidity,
        )?;
    }

    for rlt_idx in 0..remove_count {
        let real_idx_input = remove_input_base + rlt_idx;
        let real_idx_output = remove_output_base + rlt_idx * 2;

        burn_liquidity(
            real_idx_input,
            real_idx_output,
            info_type_hash,
            &info_in_data,
            pool_x_type_hash,
            pool_y_type_hash,
            sudt_x_reserve,
            sudt_y_reserve,
            total_liquidity,
        )?;
    }

    Ok(())
}

pub fn verify_initial_mint(
    info_in_type_hash: [u8; 32],
    liquidity_sudt_type_hash: [u8; 32],
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    if *sudt_x_reserve != 0 || *sudt_y_reserve != 0 || *total_liquidity != 0 {
        return Err(Error::InvalidInfoInData);
    }

    // pool_x.type_hash == req_x.type_hash
    if get_cell_type_hash!(1, Source::Input) != get_cell_type_hash!(4, Source::Input) {
        return Err(Error::InvalidSUDTXTypeHash);
    }

    // pool_y.type_hash == req_y.type_hash
    if get_cell_type_hash!(2, Source::Input) != get_cell_type_hash!(5, Source::Input) {
        return Err(Error::InvalidSUDTYTypeHash);
    }

    let req_sudt_x_cell = load_cell(4, Source::Input)?;
    let raw_sudt_x_lock_args: Vec<u8> = req_sudt_x_cell.lock().args().unpack();
    let req_sudt_x_lock_args = LiquidityRequestLockArgs::from_raw(&raw_sudt_x_lock_args)?;

    let req_sudt_y_cell = load_cell(5, Source::Input)?;
    let raw_sudt_y_lock_args: Vec<u8> = req_sudt_y_cell.lock().args().unpack();
    let req_sudt_y_lock_args = MintLiquidityRequestLockArgs::from_raw(&raw_sudt_y_lock_args)?;

    // info_in.type_hash == req_x.lock.args[0..32]
    if info_in_type_hash != req_sudt_x_lock_args.info_type_hash
        || info_in_type_hash != req_sudt_y_lock_args.info_type_hash
    {
        return Err(Error::InvalidLiquidityReqLockArgsInfoTypeHash);
    }

    // req_x.lock.args.user_lock_hash == req_y.lock.args[32..64]
    let user_lock_hash = req_sudt_x_lock_args.user_lock_hash;
    if req_sudt_y_lock_args.user_lock_hash != user_lock_hash {
        return Err(Error::UserLockHashDiff);
    }

    // req_x.lock_hash == req_y.lock.args[65..97]
    let req_sudt_x_lock_hash = load_cell_lock_hash(4, Source::Input)?;
    if req_sudt_y_lock_args.req_sudt_x_cell_lock_hash != req_sudt_x_lock_hash {
        return Err(Error::InvalidReqSUDTXLockHash);
    }

    let sudt_lp_cell = load_cell(4, Source::Output)?;
    let raw_sudt_lp_data = load_cell_data(4, Source::Output)?;

    verify_lp_output(
        4,
        user_lock_hash,
        &sudt_lp_cell,
        &raw_sudt_lp_data,
        liquidity_sudt_type_hash,
    )?;

    let expected_ckb_capcatiy = BigUint::from(req_sudt_x_cell.capacity().unpack())
        + req_sudt_y_cell.capacity().unpack()
        - MIN_SUDT_CAPACITY
        - req_sudt_x_lock_args.tips_ckb;

    verify_ckb_cell(
        5,
        Source::Output,
        expected_ckb_capcatiy.try_into().unwrap(),
        user_lock_hash,
    )?;

    let amount_x_in =
        decode_u128(&load_cell_data(4, Source::Input)?)? - req_sudt_x_lock_args.tips_sudt_x;
    let amount_y_in =
        decode_u128(&load_cell_data(5, Source::Input)?)? - req_sudt_x_lock_args.tips_sudt_y;
    let amount_lp = decode_u128(&raw_sudt_lp_data)?;

    if BigUint::from(amount_lp) != (BigUint::from(amount_x_in) * amount_y_in).sqrt() {
        return Err(Error::InvalidLpAmount);
    }

    *sudt_x_reserve = amount_x_in;
    *sudt_y_reserve = amount_y_in;
    *total_liquidity = amount_lp;

    Ok(())
}

fn burn_liquidity(
    input_idx: usize,
    output_idx: usize,
    info_type_hash: [u8; 32],
    info_in_data: &InfoCellData,
    pool_x_type_hash: [u8; 32],
    pool_y_type_hash: [u8; 32],
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    let req_lp_cell = load_cell(input_idx, Source::Input)?;
    let raw_req_lp_data = load_cell_data(input_idx, Source::Input)?;
    let sudt_x_out = load_cell(output_idx, Source::Output)?;
    let sudt_y_out = load_cell(output_idx + 1, Source::Output)?;

    if req_lp_cell.capacity().unpack() < 2 * MIN_SUDT_CAPACITY {
        return Err(Error::InvalidRemoveLpCapacity);
    }

    if raw_req_lp_data.len() < 16 {
        return Err(Error::InvalidRemoveLpDataLen);
    }

    // req_lp.type_hash == info_in.data.liquidity_sudt_type_hash
    if get_cell_type_hash!(input_idx, Source::Input) != info_in_data.liquidity_sudt_type_hash {
        return Err(Error::InvalidRemoveLpTypeHash);
    }

    let req_lp_lock_hash = load_cell_lock_hash(input_idx, Source::Input)?;
    if req_lp_lock_hash[0..32] != info_type_hash {
        return Err(Error::InvalidRemoveLpLockHash);
    }

    let raw_lock_args: Vec<u8> = req_lp_cell.lock().args().unpack();
    let req_lp_lock_args = LiquidityRequestLockArgs::from_raw(&raw_lock_args)?;
    let user_lock_hash = req_lp_lock_args.user_lock_hash;
    let tips_sudt_lp = req_lp_lock_args.tips_sudt_x;

    let sudt_x_out_data = load_cell_data(output_idx, Source::Output)?;
    let sudt_y_out_data = load_cell_data(output_idx + 1, Source::Output)?;

    verify_sudt_in_remove_output(
        output_idx,
        &sudt_x_out,
        &sudt_x_out_data,
        user_lock_hash,
        pool_x_type_hash,
    )?;

    verify_sudt_in_remove_output(
        output_idx + 1,
        &sudt_y_out,
        &sudt_x_out_data,
        user_lock_hash,
        pool_y_type_hash,
    )?;

    let amount_lp = decode_u128(&raw_req_lp_data)? - tips_sudt_lp;
    let amount_x_out = decode_u128(&sudt_x_out_data)?;
    let amount_y_out = decode_u128(&sudt_y_out_data)?;
    let amount_x_out_min = req_lp_lock_args.sudt_x_min;
    let amount_y_out_min = req_lp_lock_args.sudt_y_min;

    if amount_x_out_min == 0 || amount_x_out < amount_x_out_min {
        return Err(Error::InvalidXAmountOutMin);
    }

    if amount_y_out_min == 0 || amount_y_out < amount_y_out_min {
        return Err(Error::InvalidYAmountOutMin);
    }

    if BigUint::from(amount_x_out)
        != BigUint::from(amount_lp) * (*sudt_x_reserve) / (*total_liquidity) + ONE
    {
        return Err(Error::InvalidXAmountOut);
    }

    if BigUint::from(amount_y_out)
        != BigUint::from(amount_lp) * (*sudt_y_reserve) / (*total_liquidity) + ONE
    {
        return Err(Error::InvalidYAmountOut);
    }

    *sudt_x_reserve -= amount_x_out;
    *sudt_y_reserve -= amount_y_out;
    *total_liquidity -= amount_lp;

    Ok(())
}

fn mint_liquidity(
    input_idx: usize,
    output_idx: usize,
    info_type_hash: [u8; 32],
    info_in_data: &InfoCellData,
    pool_x_type_hash: [u8; 32],
    pool_y_type_hash: [u8; 32],
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    let req_x_cell = load_cell(input_idx, Source::Input)?;
    let req_y_cell = load_cell(input_idx + 1, Source::Input)?;
    let req_x_lock_hash = load_cell_lock_hash(input_idx, Source::Input)?;

    verify_add_liquidity_req_cells(
        input_idx,
        info_type_hash,
        pool_x_type_hash,
        pool_y_type_hash,
        req_x_lock_hash,
    )?;

    let raw_lock_args: Vec<u8> = req_x_cell.lock().args().unpack();
    let req_x_lock_args = LiquidityRequestLockArgs::from_raw(&raw_lock_args)?;
    let raw_lock_args: Vec<u8> = req_y_cell.lock().args().unpack();
    let req_y_lock_args = MintLiquidityRequestLockArgs::from_raw(&raw_lock_args)?;
    let user_lock_hash = req_x_lock_args.user_lock_hash;

    if req_y_lock_args.user_lock_hash != user_lock_hash {
        return Err(Error::InvalidLiquidityReqYLockArgsXUserHash);
    }

    if req_x_lock_hash != req_y_lock_args.req_sudt_x_cell_lock_hash {
        return Err(Error::InvalidLiquidityReqYLockArgsXLockHash);
    }

    let sudt_lp_cell = load_cell(output_idx, Source::Output)?;
    let raw_sudt_lp_data = load_cell_data(output_idx, Source::Output)?;

    let sudt_change_cell = load_cell(output_idx + 1, Source::Output)?;
    let raw_sudt_change_data = load_cell_data(output_idx + 1, Source::Output)?;

    verify_lp_output(
        output_idx,
        user_lock_hash,
        &sudt_lp_cell,
        &raw_sudt_lp_data,
        info_in_data.liquidity_sudt_type_hash,
    )?;

    verify_sudt_change_output(
        output_idx + 1,
        input_idx,
        &sudt_change_cell,
        &raw_sudt_lp_data,
        user_lock_hash,
    )?;

    let expected_ckb_capcatiy = BigUint::from(req_x_cell.capacity().unpack())
        + req_y_cell.capacity().unpack()
        - 2 * MIN_SUDT_CAPACITY
        - req_x_lock_args.tips_ckb;

    verify_ckb_cell(
        output_idx + 2,
        Source::Output,
        expected_ckb_capcatiy.try_into().unwrap(),
        user_lock_hash,
    )?;

    let amount_x =
        decode_u128(&load_cell_data(input_idx, Source::Input)?)? - req_x_lock_args.tips_sudt_x;
    let amount_y =
        decode_u128(&load_cell_data(input_idx + 1, Source::Input)?)? - req_x_lock_args.tips_sudt_y;
    let amount_x_min = req_x_lock_args.sudt_x_min;
    let amount_y_min = req_x_lock_args.sudt_y_min;
    let amount_change = decode_u128(&raw_sudt_change_data[0..16])?;
    let amount_lp = decode_u128(&raw_sudt_lp_data[0..16])?;

    if get_cell_type_hash!(input_idx + 1, Source::Input)
        == get_cell_type_hash!(output_idx + 1, Source::Output)
    {
        x_exhausted(
            amount_x,
            amount_y,
            amount_y_min,
            amount_change,
            amount_lp,
            sudt_x_reserve,
            sudt_y_reserve,
            total_liquidity,
        )?;
    } else {
        y_exhausted(
            amount_x,
            amount_y,
            amount_x_min,
            amount_change,
            amount_lp,
            sudt_x_reserve,
            sudt_y_reserve,
            total_liquidity,
        )?;
    }

    *total_liquidity += amount_lp;

    Ok(())
}

fn x_exhausted(
    amount_x: u128,
    amount_y: u128,
    amount_y_min: u128,
    amount_change: u128,
    amount_lp: u128,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    let amount_y_in = amount_y - amount_change;
    if amount_y_min == 0 || amount_y_in < amount_y_min {
        return Err(Error::InvalidYAmountMin);
    }

    if BigUint::from(amount_y_in)
        != BigUint::from(amount_x) * (*sudt_y_reserve) / (*sudt_x_reserve) + ONE
    {
        return Err(Error::InvalidXAmountMin);
    }

    if BigUint::from(amount_lp)
        != BigUint::from(amount_x) * (*total_liquidity) / (*sudt_x_reserve) + ONE
    {
        return Err(Error::InvalidLiquidityAmount);
    }

    *sudt_x_reserve += amount_x;
    *sudt_y_reserve += amount_y_in;

    Ok(())
}

fn y_exhausted(
    amount_x: u128,
    amount_y: u128,
    amount_x_min: u128,
    amount_change: u128,
    amount_lp: u128,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    let amount_x_in = amount_x - amount_change;
    if amount_x_min == 0 || amount_x_in < amount_x_min {
        return Err(Error::InvalidXAmountMin);
    }

    if BigUint::from(amount_x_in)
        != BigUint::from(amount_y) * (*sudt_x_reserve) / (*sudt_y_reserve) + ONE
    {
        return Err(Error::InvalidXAmountMin);
    }

    if BigUint::from(amount_lp)
        != BigUint::from(amount_y) * (*total_liquidity) / (*sudt_y_reserve) + ONE
    {
        return Err(Error::InvalidLiquidityAmount);
    }

    *sudt_x_reserve += amount_x_in;
    *sudt_y_reserve += amount_y;

    Ok(())
}

fn verify_sudt_in_remove_output(
    output_idx: usize,
    sudt_cell: &CellOutput,
    sudt_data: &[u8],
    user_lock_hash: [u8; 32],
    pool_type_hash: [u8; 32],
) -> Result<(), Error> {
    verify_sudt_basic(output_idx, sudt_cell, sudt_data, user_lock_hash)?;

    if get_cell_type_hash!(output_idx, Source::Output) != pool_type_hash {
        return Err(Error::InvalidSUDTOutTypeHash);
    }

    Ok(())
}

fn verify_sudt_change_output(
    output_idx: usize,
    input_idx: usize,
    sudt_change_cell: &CellOutput,
    sudt_change_data: &[u8],
    user_lock_hash: [u8; 32],
) -> Result<(), Error> {
    verify_sudt_basic(
        output_idx,
        sudt_change_cell,
        sudt_change_data,
        user_lock_hash,
    )?;

    // sudt_change.type_hash == req_x.type_hash == req_y.type_hash
    let sudt_change_type_hash = get_cell_type_hash!(output_idx, Source::Output);
    if sudt_change_type_hash != get_cell_type_hash!(input_idx, Source::Input)
        && sudt_change_type_hash != get_cell_type_hash!(input_idx + 1, Source::Input)
    {
        return Err(Error::InvalidSUDTChangeTypeHash);
    }
    Ok(())
}

fn verify_lp_output(
    idx: usize,
    user_lock_hash: [u8; 32],
    sudt_lp_cell: &CellOutput,
    raw_sudt_lp_data: &[u8],
    liquidity_sudt_type_hash: [u8; 32],
) -> Result<(), Error> {
    verify_sudt_basic(idx, sudt_lp_cell, raw_sudt_lp_data, user_lock_hash)?;

    if get_cell_type_hash!(idx, Source::Output) != liquidity_sudt_type_hash {
        return Err(Error::InvalidLpTypeHash);
    }

    Ok(())
}

fn verify_add_liquidity_req_cells(
    input_idx: usize,
    info_type_hash: [u8; 32],
    pool_x_type_hash: [u8; 32],
    pool_y_type_hash: [u8; 32],
    req_x_lock_hash: [u8; 32],
) -> Result<(), Error> {
    // req_x.type_hash == pool_x.type_hash
    if get_cell_type_hash!(input_idx, Source::Input) != pool_x_type_hash {
        return Err(Error::InvalidLiquidityReqXTypeHash);
    }

    // req_y.type_hash == pool_y.type_hash
    if get_cell_type_hash!(input_idx + 1, Source::Input) != pool_y_type_hash {
        return Err(Error::InvalidLiquidityReqYTypeHash);
    }

    if load_cell_data(input_idx, Source::Input)?.len() < 16 {
        return Err(Error::InvalidLiquidityReqXDataLen);
    }

    if load_cell_data(input_idx + 1, Source::Input)?.len() < 16 {
        return Err(Error::InvalidLiquidityReqYDataLen);
    }

    // req_x.lock_hash[0..32] == info_in.type_hash
    if req_x_lock_hash[0..32] != info_type_hash {
        return Err(Error::InvalidLiquidityReqXLockHash);
    }

    // req_y.lock_hash[0..32] == info_in.type_hash
    if load_cell_lock_hash(input_idx + 1, Source::Input)?[0..32] != info_type_hash {
        return Err(Error::InvalidLiquidityReqYLockHash);
    }

    Ok(())
}
