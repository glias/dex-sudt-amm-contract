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
    ckb_reserve: &mut u128,
    sudt_reserve: &mut u128,
    total_liquidity: &mut u128,
    liquidity_sudt_type_hash: [u8; 32],
) -> Result<(), Error> {
    let pool_type_hash = get_cell_type_hash!(1, Source::Input);
    let input_cell_count = QueryIter::new(load_cell, Source::Input).count();

    for idx in (3 + swap_cell_count)..input_cell_count {
        let liquidity_order_cell = load_cell(idx, Source::Input)?;
        let raw_data = load_cell_data(idx, Source::Input)?;
        let raw_lock_args: Vec<u8> = liquidity_order_cell.lock().args().unpack();
        let liquidity_order_lock_args = LiquidityRequestLockArgs::from_raw(&raw_lock_args)?;

        if liquidity_order_lock_args.version != INFO_VERSION {
            return Err(Error::VersionDiff);
        }

        let liquidity_order_data = SUDTAmountData::from_raw(&raw_data)?;
        let liquidity_type_hash = get_cell_type_hash!(idx, Source::Input);
        if liquidity_order_lock_args.info_type_hash != get_cell_type_hash!(0, Source::Input) {
            return Err(Error::LiquidityArgsInfoTypeHashMismatch);
        }

        if liquidity_type_hash == liquidity_sudt_type_hash {
            burn_liquidity(
                idx,
                swap_cell_count + 3,
                &liquidity_order_cell,
                liquidity_order_data.sudt_amount,
                ckb_reserve,
                sudt_reserve,
                total_liquidity,
            )?;
        } else if liquidity_type_hash == pool_type_hash {
            mint_liquidity(
                idx,
                swap_cell_count + 3,
                liquidity_sudt_type_hash,
                &liquidity_order_cell,
                liquidity_order_data.sudt_amount,
                ckb_reserve,
                sudt_reserve,
                total_liquidity,
            )?;
        } else {
            return Err(Error::UnknownLiquidity);
        }
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
    let amount_lp = load_cell_data(5, Source::Output)?;

    if BigUint::from(amount_lp) != (BigUint::from(amount_x_in) * amount_y_in).sqrt() {
        return Err(Error::InvalidLpAmount);
    }

    *sudt_x_reserve = amount_x_in;
    *sudt_y_reserve = amount_y_in;
    *total_liquidity = amount_lp;

    Ok(())
}

fn mint_liquidity(
    liquidity_cell_index: usize,
    base_index: usize,
    liquidity_sudt_type_hash: [u8; 32],
    liquidity_order_cell: &CellOutput,
    liquidity_order_data: u128,
    ckb_reserve: &mut u128,
    sudt_reserve: &mut u128,
    total_liquidity: &mut u128,
) -> Result<(), Error> {
    if *total_liquidity == 0 {
        return Err(Error::UnknownLiquidity);
    }

    let relative_index = liquidity_cell_index - base_index;
    let liquidity_index = relative_index * 2 + base_index;

    let raw_lock_args: Vec<u8> = liquidity_order_cell.lock().args().unpack();
    let liquidity_order_lock_args = LiquidityRequestLockArgs::from_raw(&raw_lock_args)?;
    let change_cell = load_cell(liquidity_index + 1, Source::Output)?;
    let change_lock_hash = load_cell_lock_hash(liquidity_index + 1, Source::Output)?;

    if get_cell_type_hash!(liquidity_index, Source::Output) != liquidity_sudt_type_hash {
        return Err(Error::LiquiditySUDTTypeHashMismatch);
    }

    if load_cell_lock_hash(liquidity_index, Source::Output)?
        != liquidity_order_lock_args.user_lock_hash
    {
        return Err(Error::LiquidityArgsUserLockHashMismatch);
    }

    let user_liquidity =
        SUDTAmountData::from_raw(&load_cell_data(liquidity_index, Source::Output)?)?.sudt_amount;

    let ckb_injected: u128;
    let sudt_injected: u128;
    let change_data = load_cell_data(liquidity_index + 1, Source::Output)?;

    if change_data.is_empty() {
        if change_cell.type_().is_some()
            || change_lock_hash != liquidity_order_lock_args.user_lock_hash
        {
            return Err(Error::InvalidChangeCell);
        }

        sudt_injected = liquidity_order_data;
        ckb_injected = liquidity_order_cell.capacity().unpack() as u128
            - SUDT_CAPACITY as u128
            - change_cell.capacity().unpack() as u128;

        if BigUint::from(ckb_injected)
            != (BigUint::from(sudt_injected) * (*ckb_reserve) / *sudt_reserve) + ONE
        {
            return Err(Error::LiquidityPoolTokenDiff);
        }

        let min_ckb_injected = liquidity_order_lock_args.amount_0 as u128;
        if min_ckb_injected == 0 || ckb_injected < min_ckb_injected {
            return Err(Error::InvalidMinCkbInject);
        }

        if BigUint::from(user_liquidity)
            != (BigUint::from(sudt_injected) * (*total_liquidity) / *sudt_reserve) + ONE
        {
            return Err(Error::SUDTInjectAmountDiff);
        }
    } else if change_data.len() >= 16 {
        if get_cell_type_hash!(liquidity_index + 1, Source::Output)
            != get_cell_type_hash!(1, Source::Input)
        {
            return Err(Error::SUDTTypeHashMismatch);
        }

        if change_lock_hash != liquidity_order_lock_args.user_lock_hash {
            return Err(Error::LiquidityArgsUserLockHashMismatch);
        }

        sudt_injected = liquidity_order_data - decode_u128(&change_data[0..16])?;
        ckb_injected = (liquidity_order_cell.capacity().unpack() - SUDT_CAPACITY * 2) as u128;

        if BigUint::from(sudt_injected)
            != (BigUint::from(ckb_injected) * (*sudt_reserve) / (*ckb_reserve)) + ONE
        {
            return Err(Error::LiquidityPoolTokenDiff);
        }

        let min_sudt_injected = liquidity_order_lock_args.amount_1;
        if min_sudt_injected == 0 || sudt_injected < min_sudt_injected {
            return Err(Error::InvalidMinSUDTInject);
        }

        if BigUint::from(user_liquidity)
            != (BigUint::from(ckb_injected) * (*total_liquidity) / (*ckb_reserve)) + ONE
        {
            return Err(Error::CKBInjectAmountDiff);
        }
    } else {
        return Err(Error::InvalidChangeCell);
    }

    *ckb_reserve += ckb_injected;
    *sudt_reserve += sudt_injected;
    *total_liquidity += user_liquidity;

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
