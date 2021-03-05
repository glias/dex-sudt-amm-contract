mod liquidity_verify;
mod swap_verify;
mod utils;

use alloc::vec::Vec;
use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use share::cell::{InfoCellData, SUDTAmountData};
use share::ckb_std::{
    ckb_constants::Source,
    ckb_types::{
        packed::{Byte, CellOutput},
        prelude::*,
    },
    default_alloc,
    high_level::{
        load_cell, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script,
        load_witness_args, QueryIter,
    },
};
use share::{blake2b, decode_u64, get_cell_type_hash, hash::blake2b_256};

use crate::error::Error;

const ONE: u128 = 1;
const THOUSAND: u128 = 1_000;
const FEE_RATE: u128 = 997;
const POOL_CAPACITY: u64 = 16_200_000_000;
// const SUDT_CAPACITY: u64 = 14_200_000_000;
const MIN_SUDT_CAPACITY: u64 = 14_200_000_000;
const INFO_CAPACITY: u64 = 25_000_000_000;
const BASE_CELL_COUNT: usize = 4;
// const INFO_VERSION: u8 = 1;

pub static INFO_LOCK_CODE_HASH: &str =
    include!(concat!(env!("OUT_DIR"), "/info_lock_code_hash.rs"));

// Alloc 4K fast HEAP + 2M HEAP to receives PrefilledData
default_alloc!(4 * 1024, 2048 * 1024, 64);

pub fn main() -> Result<(), Error> {
    let info_type_code_hash = load_script()?.code_hash().unpack();
    let (input_info_cell_count, output_info_cell_count) = get_info_count(info_type_code_hash);

    // verify info creation
    if input_info_cell_count == 0 && output_info_cell_count == 1 {
        return verify_info_creation(&load_cell(0, Source::Output)?);
    }

    if input_info_cell_count != 1 || output_info_cell_count != 1 {
        return Err(Error::MoreThanOneInfoCell);
    }

    let info_in_cell = load_cell(0, Source::Input)?;
    let info_in_data = InfoCellData::from_raw(&load_cell_data(0, Source::Input)?)?;
    let pool_x_in_cell = load_cell(1, Source::Input)?;
    let pool_x_in_data = SUDTAmountData::from_raw(&load_cell_data(1, Source::Input)?)?;
    let pool_y_in_cell = load_cell(2, Source::Input)?;
    let pool_y_in_data = SUDTAmountData::from_raw(&load_cell_data(2, Source::Input)?)?;
    let info_out_cell = load_cell(0, Source::Output)?;
    let info_out_data = InfoCellData::from_raw(&load_cell_data(0, Source::Output)?)?;
    let pool_x_out_cell = load_cell(1, Source::Output)?;
    let pool_x_out_data = SUDTAmountData::from_raw(&load_cell_data(1, Source::Output)?)?;
    let pool_y_out_cell = load_cell(2, Source::Output)?;
    let pool_y_out_data = SUDTAmountData::from_raw(&load_cell_data(1, Source::Output)?)?;

    let info_in_lock_hash = load_cell_lock_hash(0, Source::Input)?;
    let info_out_lock_hash = load_cell_lock_hash(0, Source::Output)?;

    // basic verify
    verify_info_in(
        &info_in_cell,
        &info_in_data,
        &pool_x_in_data,
        &pool_y_in_data,
    )?;

    verify_info_out(
        &info_out_cell,
        &info_out_data,
        info_in_lock_hash,
        info_out_lock_hash,
        &pool_x_out_data,
        &pool_y_out_data,
    )?;

    verify_pool_in_cell(&pool_x_in_cell, 1, info_in_lock_hash)?;
    verify_pool_in_cell(&pool_y_in_cell, 2, info_in_lock_hash)?;
    verify_pool_out_cell(&pool_x_out_cell, 1)?;
    verify_pool_out_cell(&pool_y_out_cell, 2)?;

    let mut sudt_x_reserve = info_in_data.sudt_x_reserve;
    let mut sudt_y_reserve = info_in_data.sudt_y_reserve;
    let mut total_liquidity = info_in_data.total_liquidity;

    let raw_witness: Vec<u8> = load_witness_args(0, Source::Input)?
        .input_type()
        .to_opt()
        .unwrap()
        .unpack();
    let swap_cell_count = decode_u64(&raw_witness[0..16])? as usize;
    let add_liquidity_count = decode_u64(&raw_witness[16..32])? as usize;
    let input_cell_count = QueryIter::new(load_cell, Source::Input).count();
    let output_cell_count = QueryIter::new(load_cell, Source::Output).count();

    if input_cell_count == 6 && output_cell_count == 6 {
        liquidity_verify::verify_initial_mint(
            info_in_data.liquidity_sudt_type_hash,
            &mut sudt_x_reserve,
            &mut sudt_y_reserve,
            &mut total_liquidity,
        )?;
    } else {
        swap_verify::swap_tx_verification(
            swap_cell_count,
            &mut sudt_x_reserve,
            &mut sudt_y_reserve,
        )?;

        liquidity_verify::liquidity_tx_verification(
            swap_cell_count,
            add_liquidity_count,
            input_cell_count,
            info_in_data,
            &mut sudt_x_reserve,
            &mut sudt_y_reserve,
            &mut total_liquidity,
        )?;
    }

    verify_eventual_data(
        info_out_data,
        sudt_x_reserve,
        sudt_y_reserve,
        total_liquidity,
    )?;

    Ok(())
}

fn verify_eventual_data(
    info_out_data: InfoCellData,
    sudt_x_reserve: u128,
    sudt_y_reserve: u128,
    total_liquidity: u128,
) -> Result<(), Error> {
    if info_out_data.sudt_x_reserve != sudt_x_reserve {
        return Err(Error::InvalidSUDTXReserve);
    }

    if info_out_data.sudt_y_reserve != sudt_y_reserve {
        return Err(Error::InvalidSUDTYReserve);
    }

    if info_out_data.total_liquidity != total_liquidity {
        return Err(Error::InvalidTotalLiquidity);
    }

    Ok(())
}

fn get_info_count(info_type_code_hash: [u8; 32]) -> (usize, usize) {
    let input_count = QueryIter::new(load_cell, Source::Input)
        .filter(|cell| {
            cell.type_().to_opt().map_or_else(
                || false,
                |script| script.code_hash().unpack() == info_type_code_hash,
            )
        })
        .count();
    let output_count = QueryIter::new(load_cell, Source::Output)
        .filter(|cell| {
            cell.type_().to_opt().map_or_else(
                || false,
                |script| script.code_hash().unpack() == info_type_code_hash,
            )
        })
        .count();

    (input_count, output_count)
}

fn verify_info_in(
    info_in_cell: &CellOutput,
    info_in_data: &InfoCellData,
    pool_x_data: &SUDTAmountData,
    pool_y_data: &SUDTAmountData,
) -> Result<(), Error> {
    if info_in_cell.capacity().unpack() != INFO_CAPACITY {
        return Err(Error::InfoCapacityDiff);
    }

    if info_in_data.sudt_x_reserve != pool_x_data.sudt_amount {
        return Err(Error::PoolXAmountDiff);
    }

    if info_in_data.sudt_y_reserve != pool_y_data.sudt_amount {
        return Err(Error::PoolYAmountDiff);
    }

    Ok(())
}

fn verify_info_out(
    info_out_cell: &CellOutput,
    info_out_data: &InfoCellData,
    info_in_lock_hash: [u8; 32],
    info_out_lock_hash: [u8; 32],
    pool_x_data: &SUDTAmountData,
    pool_y_data: &SUDTAmountData,
) -> Result<(), Error> {
    if info_out_cell.capacity().unpack() != INFO_CAPACITY {
        return Err(Error::InfoCapacityDiff);
    }

    if info_out_data.sudt_x_reserve != pool_x_data.sudt_amount {
        return Err(Error::PoolXAmountDiff);
    }

    if info_out_data.sudt_y_reserve != pool_y_data.sudt_amount {
        return Err(Error::PoolYAmountDiff);
    }

    if get_cell_type_hash!(0, Source::Input) != get_cell_type_hash!(0, Source::Output) {
        return Err(Error::InfoCellTypeHashDiff);
    }

    if info_in_lock_hash != info_out_lock_hash {
        return Err(Error::InfoCellLockHashDiff);
    }

    Ok(())
}

fn verify_pool_in_cell(
    pool_cell: &CellOutput,
    index: usize,
    info_in_lock_hash: [u8; 32],
) -> Result<(), Error> {
    if pool_cell.capacity().unpack() != POOL_CAPACITY {
        return Err(Error::InvalidPoolInCapacity);
    }

    if load_cell_lock_hash(index, Source::Input)? != info_in_lock_hash {
        return Err(Error::InvalidPoolInLockHash);
    }

    Ok(())
}

fn verify_pool_out_cell(pool_cell: &CellOutput, index: usize) -> Result<(), Error> {
    if pool_cell.capacity().unpack() != POOL_CAPACITY {
        return Err(Error::InvalidPoolInCapacity);
    }

    if get_cell_type_hash!(index, Source::Input) != get_cell_type_hash!(0, Source::Output) {
        return Err(Error::PoolCellTypeHashDiff);
    }

    if load_cell_lock_hash(index, Source::Input)? != load_cell_lock_hash(index, Source::Output)? {
        return Err(Error::PoolCellLockHashDiff);
    }

    Ok(())
}

fn verify_info_creation(info_out_cell: &CellOutput) -> Result<(), Error> {
    let info_lock_code_hash = hex::decode(INFO_LOCK_CODE_HASH).unwrap();
    let info_cell_in_deps_count = QueryIter::new(load_cell_type_hash, Source::CellDep)
        .filter(|res| {
            if let Some(hash) = res {
                Vec::from(*hash) == info_lock_code_hash
            } else {
                false
            }
        })
        .count();

    if info_cell_in_deps_count == 0 {
        return Err(Error::NoInfoCellInDeps);
    }

    let info_lock_count = QueryIter::new(load_cell_data, Source::CellDep)
        .filter(|data| blake2b_256(data) == info_lock_code_hash.as_ref())
        .count();

    if info_lock_count != 3 {
        return Err(Error::InvalidInfoCellDepsCount);
    }

    if get_cell_type_hash!(1, Source::Output) == get_cell_type_hash!(2, Source::Output) {
        return Err(Error::SameSUDTInPair);
    }

    if info_out_cell.lock().hash_type() != HashType::Code.into() {
        return Err(Error::InvalidLockScriptHashType);
    }

    let info_out_lock_args: Vec<u8> = info_out_cell.lock().args().unpack();
    let pool_x_type_hash = get_cell_type_hash!(1, Source::Output);
    let pool_y_type_hash = get_cell_type_hash!(2, Source::Output);

    if info_out_lock_args[0..32] != blake2b!(pool_x_type_hash, pool_y_type_hash) {
        return Err(Error::PoolTypeHashMismatch);
    }

    if info_out_lock_args[32..64] != get_cell_type_hash!(0, Source::Output) {
        return Err(Error::InfoTypeHashMismatch);
    }

    verify_output_pools()
}

fn verify_output_pools() -> Result<(), Error> {
    let pool_x = load_cell(1, Source::Output)?;
    let pool_y = load_cell(2, Source::Output)?;

    if pool_x.capacity().unpack() != POOL_CAPACITY || pool_y.capacity().unpack() != POOL_CAPACITY {
        return Err(Error::InvalidPoolOutCapacity);
    }

    if load_cell_data(1, Source::Output)?.len() < 16
        || load_cell_data(2, Source::Output)?.len() < 16
    {
        return Err(Error::InvalidPoolOutputData);
    }

    let info_out_lock_hash = load_cell_lock_hash(0, Source::Output)?;
    let pool_x_lock_hash = load_cell_lock_hash(1, Source::Output)?;
    let pool_y_type_hash = get_cell_type_hash!(2, Source::Output);

    if info_out_lock_hash != pool_x_lock_hash || pool_x_lock_hash != pool_y_type_hash {
        return Err(Error::InvalidOutputLockHash);
    }

    Ok(())
}

#[allow(dead_code)]
enum HashType {
    Data,
    Code,
}

impl Into<Byte> for HashType {
    fn into(self) -> Byte {
        match self {
            HashType::Data => Byte::new(0u8),
            HashType::Code => Byte::new(1u8),
        }
    }
}
