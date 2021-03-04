use alloc::vec::Vec;
use core::convert::TryInto;
use core::result::Result;
use num_traits::real::Real;

use num_bigint::BigUint;
use num_traits::identities::Zero;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use share::cell::{
    InfoCellData, LiquidityRequestLockArgs, MintLiquidityRequestLockArgs, SUDTAmountData,
};
use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::CellOutput, prelude::*},
    high_level::{load_cell, load_cell_data, load_cell_lock_hash, QueryIter},
};
use share::{decode_u128, get_cell_type_hash};

use crate::entry::utils::verify_ckb_cell;
use crate::entry::{INFO_VERSION, MIN_SUDT_CAPACITY, ONE, SUDT_CAPACITY};
use crate::error::Error;

pub fn liquidity_tx_verification(
    swap_cell_count: usize,
    add_liquidity_count: usize,
    input_cell_count: usize,
    info_in_data: InfoCellData,
    liquidity_sudt_type_hash: [u8; 32],
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    if *total_liquidity == 0 {
        return Err(Error::TotalLiquidityIsZero);
    }

    let add_input_base = 4 + swap_cell_count;
    let add_output_base = 4 + swap_cell_count * 2;
    let remove_input_base = 4 + swap_cell_count + add_liquidity_count * 2;
    let remove_output_base = 4 + swap_cell_count * 2 * add_liquidity_count * 3;
    let remove_count = input_cell_count - remove_input_base;
    let pool_x_type_hash = get_cell_type_hash!(1, Source::Input);
    let pool_y_type_hash = get_cell_type_hash!(2, Source::Input);

    for abs_idx in (0..add_liquidity_count * 2).step_by(2) {
        let real_idx_input = abs_idx + add_input_base;
        let real_idx_output = add_output_base + (abs_idx / 2) * 3;
        let info_type_hash = get_cell_type_hash!(0, Source::Input);

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

    for abs_idx in 0..remove_count {
        
    }

    Ok(())
}

pub fn verify_initial_mint(
    liquidity_sudt_type_hash: [u8; 32],
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    if *sudt_x_reserve != 0 || *sudt_y_reserve != 0 || *total_liquidity != 0 {
        return Err(Error::InvalidInfoInData);
    }

    if get_cell_type_hash!(1, Source::Input) != get_cell_type_hash!(4, Source::Input) {
        return Err(Error::InvalidSUDTXTypeHash);
    }

    if get_cell_type_hash!(2, Source::Input) != get_cell_type_hash!(5, Source::Input) {
        return Err(Error::InvalidSUDTYTypeHash);
    }

    // Todo: perf
    let info_in_type_hash = get_cell_type_hash!(0, Source::Input);
    let req_sudt_x_cell = load_cell(4, Source::Input)?;
    let raw_sudt_x_lock_args: Vec<u8> = req_sudt_x_cell.lock().args().unpack();
    let req_sudt_x_lock_args = LiquidityRequestLockArgs::from_raw(&raw_sudt_x_lock_args)?;
    let req_sudt_y_cell = load_cell(5, Source::Input)?;
    let raw_sudt_y_lock_args: Vec<u8> = req_sudt_y_cell.lock().args().unpack();
    let req_sudt_y_lock_args = MintLiquidityRequestLockArgs::from_raw(&raw_sudt_y_lock_args)?;

    if info_in_type_hash != req_sudt_x_lock_args.info_type_hash
        || info_in_type_hash != req_sudt_y_lock_args.info_type_hash
    {
        return Err(Error::InvalidLiquidityReqLockArgsInfoTypeHash);
    }

    let user_lock_hash = req_sudt_x_lock_args.user_lock_hash;
    if req_sudt_y_lock_args.user_lock_hash != user_lock_hash {
        return Err(Error::UserLockHashDiff);
    }

    let req_sudt_x_lock_hash = load_cell_lock_hash(4, Source::Input)?;
    if req_sudt_y_lock_args.req_sudt_x_cell_lock_hash != req_sudt_x_lock_hash {
        return Err(Error::InvalidReqSUDTXLockHash);
    }

    let sudt_lp_cell = load_cell(4, Source::Output)?;
    let ckb_change_cell = load_cell(5, Source::Output)?;

    if sudt_lp_cell.capacity().unpack() != MIN_SUDT_CAPACITY {
        return Err(Error::InvalidLpCapacity);
    }

    if load_cell_data(4, Source::Output)?.len() < 16 {
        return Err(Error::InvalidLpDataLen);
    }

    if get_cell_type_hash!(4, Source::Output) != user_lock_hash {
        return Err(Error::InvalidLpTypeHash);
    }

    if load_cell_lock_hash(4, Source::Output)? != liquidity_sudt_type_hash {
        return Err(Error::InvalidLpLockHash);
    }

    verify_ckb_cell(5, Source::Output, user_lock_hash)?;

    if BigUint::from(ckb_change_cell.capacity().unpack())
        != BigUint::from(req_sudt_x_cell.capacity().unpack()) + req_sudt_y_cell.capacity().unpack()
            - MIN_SUDT_CAPACITY
            - req_sudt_x_lock_args.tips_ckb
    {
        return Err(Error::InvalidCKBChangeCapacity);
    }

    let amount_x_in =
        decode_u128(&load_cell_data(4, Source::Input)?)? - req_sudt_x_lock_args.tips_sudt_x;
    let amount_y_in =
        decode_u128(&load_cell_data(5, Source::Input)?)? - req_sudt_x_lock_args.tips_sudt_y;
    let amount_lp = decode_u128(&load_cell_data(5, Source::Output)?)?;

    if BigUint::from(amount_lp) != (BigUint::from(amount_x_in) * amount_y_in).sqrt() {
        return Err(Error::InvalidLpAmount);
    }

    *sudt_x_reserve = amount_x_in;
    *sudt_y_reserve = amount_y_in;
    *total_liquidity = amount_lp;

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
    let req_y_cell = load_cell(input_idx, Source::Input)?;
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

    if req_x_lock_hash != req_y_lock_args.req_sudt_x_cell_lock_hash {
        return Err(Error::InvalidLiquidityReqYLockArgsXLockHash);
    }

    let sudt_lp_cell = load_cell(output_idx, Source::Output)?;
    let raw_sudt_lp_data = load_cell_data(output_idx, Source::Output)?;
    let sudt_change_cell = load_cell(output_idx + 1, Source::Output)?;
    let raw_sudt_change_data = load_cell_data(output_idx, Source::Output)?;

    verify_lp_output(
        output_idx,
        user_lock_hash,
        &sudt_lp_cell,
        &raw_sudt_lp_data,
        info_in_data,
    )?;

    verify_sudt_change_output(
        output_idx + 1,
        input_idx,
        &raw_sudt_lp_data,
        user_lock_hash,
        &sudt_change_cell,
    )?;

    verify_ckb_cell(output_idx + 2, Source::Output, user_lock_hash)?;

    let amount_x =
        decode_u128(&load_cell_data(input_idx, Source::Input)?)? - req_x_lock_args.tips_sudt_x;
    let amount_y =
        decode_u128(&load_cell_data(input_idx + 1, Source::Input)?)? - req_x_lock_args.tips_sudt_y;
    let amount_x_min = req_x_lock_args.sudt_x_min;
    let amount_y_min = req_x_lock_args.sudt_y_min;
    let amount_change = decode_u128(&raw_sudt_change_data[0..16])?;
    let amount_lp = decode_u128(&raw_sudt_lp_data[0..16])?;

    if get_cell_type_hash!(output_idx + 1, Source::Output)
        == req_y_lock_args.req_sudt_x_cell_lock_hash
    {
        x_exhausted(
            amount_x,
            amount_y,
            amount_x_min,
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
            amount_y_min,
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
    amount_x_min: u128,
    amount_y_min: u128,
    amount_change: u128,
    amount_lp: u128,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    let amount_y_in = amount_y - amount_change;
    if amount_y_min == 0 || amount_y_in < amount_y_min {
        return Err(Error::InvalidYAmount);
    }

    if BigUint::from(amount_y_in)
        != BigUint::from(amount_x) * (*sudt_y_reserve) / (*sudt_x_reserve) + ONE
    {
        return Err(Error::InvalidXAmount);
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
    amount_y_min: u128,
    amount_change: u128,
    amount_lp: u128,
    sudt_x_reserve: &mut u128,
    sudt_y_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    let amount_x_in = amount_x - amount_change;
    if amount_x_min == 0 || amount_x_in < amount_x_min {
        return Err(Error::InvalidXAmount);
    }

    if BigUint::from(amount_x_in)
        != BigUint::from(amount_y) * (*sudt_x_reserve) / (*sudt_y_reserve) + ONE
    {
        return Err(Error::InvalidXAmount);
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

fn verify_sudt_change_output(
    output_idx: usize,
    input_idx: usize,
    sudt_change_data: &[u8],
    user_lock_hash: [u8; 32],
    sudt_change_cell: &CellOutput,
) -> Result<(), Error> {
    if sudt_change_cell.capacity().unpack() != MIN_SUDT_CAPACITY {
        return Err(Error::InvalidSUDTChangeCapacity);
    }

    if sudt_change_data.len() < 16 {
        return Err(Error::InvalidSUDTChangeDataLen);
    }

    if load_cell_lock_hash(output_idx, Source::Output)? != user_lock_hash {
        return Err(Error::InvalidSUDTChangeLockHash);
    }

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
    info_in_data: &InfoCellData,
) -> Result<(), Error> {
    if sudt_lp_cell.capacity().unpack() != MIN_SUDT_CAPACITY {
        return Err(Error::InvalidLpCapacity);
    }
    if raw_sudt_lp_data.len() < 16 {
        return Err(Error::InvalidLpDataLen);
    }
    if get_cell_type_hash!(idx, Source::Output) != info_in_data.liquidity_sudt_type_hash {
        return Err(Error::InvalidLpTypeHash);
    }
    Ok(
        if load_cell_lock_hash(idx, Source::Output)? != user_lock_hash {
            return Err(Error::InvalidLpLockHash);
        },
    )
}

fn verify_add_liquidity_req_cells(
    input_idx: usize,
    info_type_hash: [u8; 32],
    pool_x_type_hash: [u8; 32],
    pool_y_type_hash: [u8; 32],
    req_x_lock_hash: [u8; 32],
) -> Result<(), Error> {
    if get_cell_type_hash!(input_idx, Source::Input) != pool_x_type_hash {
        return Err(Error::InvalidLiquidityReqXTypeHash);
    }
    if get_cell_type_hash!(input_idx + 1, Source::Input) != pool_y_type_hash {
        return Err(Error::InvalidLiquidityReqYTypeHash);
    }
    if load_cell_data(input_idx, Source::Input)?.len() < 16 {
        return Err(Error::InvalidLiquidityReqXDataLen);
    }
    if load_cell_data(input_idx + 1, Source::Input)?.len() < 16 {
        return Err(Error::InvalidLiquidityReqYDataLen);
    }

    if req_x_lock_hash != info_type_hash {
        return Err(Error::InvalidLiquidityReqXLockHash);
    }
    if load_cell_lock_hash(input_idx + 1, Source::Input)? != info_type_hash {
        return Err(Error::InvalidLiquidityReqYLockHash);
    }

    Ok(())
}

fn burn_liquidity(
    index: usize,
    base_index: usize,
    liquidity_order_cell: &CellOutput,
    liquidity_order_data: u128,
    ckb_reserve: &mut u128,
    sudt_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    if *total_liquidity == 0 || liquidity_order_data == 0 {
        return Err(Error::BurnLiquidityFailed);
    }

    let relative_index = index - base_index;
    let sudt_index = relative_index * 2 + base_index;

    let sudt_out = load_cell(sudt_index, Source::Output)?;
    let ckb_out = load_cell(sudt_index + 1, Source::Output)?;
    let sudt_data = load_cell_data(index, Source::Output)?;
    let raw_lock_args: Vec<u8> = liquidity_order_cell.lock().args().unpack();
    let liquidity_lock_args = LiquidityRequestLockArgs::from_raw(&raw_lock_args)?;

    if sudt_data.len() < 16 {
        return Err(Error::SUDTCellDataLenTooShort);
    }

    if !load_cell_data(sudt_index + 1, Source::Output)?.is_empty() {
        return Err(Error::CKBCellDataIsNotEmpty);
    }

    if get_cell_type_hash!(sudt_index, Source::Output) != get_cell_type_hash!(1, Source::Input) {
        return Err(Error::SUDTTypeHashMismatch);
    }

    if load_cell_lock_hash(sudt_index, Source::Output)? != liquidity_lock_args.user_lock_hash {
        return Err(Error::AddLiquiditySUDTOutLockHashMismatch);
    }

    if load_cell_lock_hash(sudt_index + 1, Source::Output)? != liquidity_lock_args.user_lock_hash {
        return Err(Error::AddLiquidityCkbOutLockHashMismatch);
    }

    let user_ckb_got = BigUint::from(sudt_out.capacity().unpack()) + ckb_out.capacity().unpack()
        - liquidity_order_cell.capacity().unpack();
    let user_sudt_got = BigUint::from(decode_u128(&sudt_data[0..16])?);
    let burned_liquidity = liquidity_order_data;

    let min_ckb_got = BigUint::from(liquidity_lock_args.amount_0);
    let min_sudt_got = BigUint::from(liquidity_lock_args.amount_1);
    let zero = BigUint::zero();

    if min_ckb_got == zero || user_ckb_got < min_ckb_got {
        return Err(Error::InvalidMinCkbGot);
    }

    if user_sudt_got < min_sudt_got {
        return Err(Error::InvalidMinSUDTGot);
    }

    if user_ckb_got != (BigUint::from(*ckb_reserve) * burned_liquidity / *total_liquidity) + ONE {
        return Err(Error::CKBGotAmountDiff);
    }

    if user_sudt_got != (BigUint::from(*sudt_reserve) * burned_liquidity / *total_liquidity) + ONE {
        return Err(Error::SUDTGotAmountDiff);
    }

    let user_ckb_got: u128 = user_ckb_got.try_into().unwrap();
    let user_sudt_got: u128 = user_sudt_got.try_into().unwrap();

    *ckb_reserve -= user_ckb_got;
    *sudt_reserve -= user_sudt_got;
    *total_liquidity -= burned_liquidity;

    Ok(())
}
