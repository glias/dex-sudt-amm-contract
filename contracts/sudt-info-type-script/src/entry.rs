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

const INFO_INDEX: usize = 0;
const POOL_X_INDEX: usize = 1;
const POOL_Y_INDEX: usize = 2;
const SUDT_DATA_LEN: usize = 16;
const ONE: u128 = 1;
const THOUSAND: u128 = 1_000;
const FEE_RATE: u128 = 997;
const POOL_CAPACITY: u64 = 18_600_000_000;
const MIN_SUDT_CAPACITY: u64 = 14_200_000_000;
const INFO_CAPACITY: u64 = 25_000_000_000;
const BASE_CELL_COUNT: usize = 4;
const VERSION: u8 = 1;

pub static INFO_LOCK_DATA_HASH: &str =
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

    let info_in_cell = load_cell(INFO_INDEX, Source::Input)?;
    let info_in_data = InfoCellData::from_raw(&load_cell_data(INFO_INDEX, Source::Input)?)?;
    let pool_x_in_cell = load_cell(POOL_X_INDEX, Source::Input)?;
    let pool_x_in_data = SUDTAmountData::from_raw(&load_cell_data(POOL_X_INDEX, Source::Input)?)?;
    let pool_y_in_cell = load_cell(POOL_Y_INDEX, Source::Input)?;
    let pool_y_in_data = SUDTAmountData::from_raw(&load_cell_data(POOL_Y_INDEX, Source::Input)?)?;
    let info_out_cell = load_cell(INFO_INDEX, Source::Output)?;
    let info_out_data = InfoCellData::from_raw(&load_cell_data(INFO_INDEX, Source::Output)?)?;
    let pool_x_out_cell = load_cell(POOL_X_INDEX, Source::Output)?;
    let pool_x_out_data = SUDTAmountData::from_raw(&load_cell_data(POOL_X_INDEX, Source::Output)?)?;
    let pool_y_out_cell = load_cell(POOL_Y_INDEX, Source::Output)?;
    let pool_y_out_data = SUDTAmountData::from_raw(&load_cell_data(POOL_Y_INDEX, Source::Output)?)?;

    let info_in_type_hash = get_cell_type_hash!(INFO_INDEX, Source::Input);
    let info_in_lock_hash = load_cell_lock_hash(INFO_INDEX, Source::Input)?;
    let info_out_lock_hash = load_cell_lock_hash(INFO_INDEX, Source::Output)?;
    let pool_x_in_type_hash = get_cell_type_hash!(POOL_X_INDEX, Source::Input);
    let pool_y_in_type_hash = get_cell_type_hash!(POOL_Y_INDEX, Source::Input);

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
        info_in_type_hash,
        info_in_lock_hash,
        info_out_lock_hash,
        &pool_x_out_data,
        &pool_y_out_data,
    )?;

    verify_pool_in_cell(&pool_x_in_cell, POOL_X_INDEX, info_in_lock_hash)?;
    verify_pool_in_cell(&pool_y_in_cell, POOL_Y_INDEX, info_in_lock_hash)?;
    verify_pool_out_cell(&pool_x_out_cell, POOL_X_INDEX)?;
    verify_pool_out_cell(&pool_y_out_cell, POOL_Y_INDEX)?;

    let mut sudt_x_reserve = info_in_data.sudt_x_reserve;
    let mut sudt_y_reserve = info_in_data.sudt_y_reserve;
    let mut total_liquidity = info_in_data.total_liquidity;

    let raw_witness: Vec<u8> = load_witness_args(0, Source::Input)?
        .input_type()
        .to_opt()
        .unwrap()
        .unpack();
    let swap_cell_count = decode_u64(&raw_witness[0..8])? as usize;
    let add_liquidity_count = decode_u64(&raw_witness[8..16])? as usize;
    let input_cell_count = QueryIter::new(load_cell, Source::Input).count();
    let output_cell_count = QueryIter::new(load_cell, Source::Output).count();

    if input_cell_count == 6 && output_cell_count == 6 {
        liquidity_verify::verify_initial_mint(
            info_in_type_hash,
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
            pool_x_in_type_hash,
            pool_y_in_type_hash,
        )?;

        liquidity_verify::liquidity_tx_verification(
            info_in_type_hash,
            swap_cell_count,
            add_liquidity_count,
            input_cell_count,
            info_in_data,
            &mut sudt_x_reserve,
            &mut sudt_y_reserve,
            &mut total_liquidity,
            pool_x_in_type_hash,
            pool_y_in_type_hash,
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
    info_in_type_hash: [u8; 32],
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

    if info_in_type_hash != get_cell_type_hash!(INFO_INDEX, Source::Output) {
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

    if get_cell_type_hash!(index, Source::Input) != get_cell_type_hash!(index, Source::Output) {
        return Err(Error::PoolCellTypeHashDiff);
    }

    if load_cell_lock_hash(index, Source::Input)? != load_cell_lock_hash(index, Source::Output)? {
        return Err(Error::PoolCellLockHashDiff);
    }

    Ok(())
}

fn verify_info_creation(info_out_cell: &CellOutput) -> Result<(), Error> {
    let (info_lock_count, is_data_deploy) = get_info_cell_count()?;

    if info_lock_count != 3 {
        if is_data_deploy {
            return Err(Error::InvalidInfoLockInOutputCount);
        } else {
            return Err(Error::InvalidInfoLockInDepsCount);
        }
    }

    if get_cell_type_hash!(1, Source::Output) == get_cell_type_hash!(2, Source::Output) {
        return Err(Error::SameSUDTInPair);
    }

    let info_out_lock_args: Vec<u8> = info_out_cell.lock().args().unpack();
    let pool_x_type_hash = get_cell_type_hash!(POOL_X_INDEX, Source::Output);
    let pool_y_type_hash = get_cell_type_hash!(POOL_Y_INDEX, Source::Output);

    if info_out_lock_args[0..32] != blake2b!(pool_x_type_hash, pool_y_type_hash) {
        return Err(Error::PoolTypeHashMismatch);
    }

    if info_out_lock_args[32..64] != get_cell_type_hash!(0, Source::Output) {
        return Err(Error::InfoTypeHashMismatch);
    }

    verify_output_pools()
}

fn get_info_cell_count() -> Result<(usize, bool), Error> {
    let info_lock_data_hash = hex::decode(INFO_LOCK_DATA_HASH).unwrap();

    let ret =
        if load_cell(INFO_INDEX, Source::Output)?.lock().hash_type() == HashType::Code.as_byte() {
            let is_data_deploy = false;
            (type_deploy(&info_lock_data_hash)?, is_data_deploy)
        } else {
            let count = QueryIter::new(load_cell, Source::Output)
                .filter(|cell| cell.lock().code_hash().unpack() == info_lock_data_hash.as_ref())
                .count();
            (count, true)
        };

    Ok(ret)
}

fn type_deploy(info_lock_data_hash: &[u8]) -> Result<usize, Error> {
    let mut flag = false;
    let info_lock_code_hash = load_cell(INFO_INDEX, Source::Output)?
        .lock()
        .code_hash()
        .unpack();

    for (idx, res) in QueryIter::new(load_cell_type_hash, Source::CellDep).enumerate() {
        if let Some(hash) = res {
            if hash == info_lock_code_hash
                && blake2b_256(load_cell_data(idx, Source::CellDep)?) == info_lock_data_hash
            {
                flag = true;
                break;
            }
        }
    }

    if flag {
        let ret = QueryIter::new(load_cell, Source::Output)
            .filter(|cell| cell.lock().code_hash().unpack() == info_lock_code_hash)
            .count();
        Ok(ret)
    } else {
        Err(Error::NoInfoLockInCellDeps)
    }
}

fn verify_output_pools() -> Result<(), Error> {
    let pool_x = load_cell(POOL_X_INDEX, Source::Output)?;
    let pool_y = load_cell(POOL_Y_INDEX, Source::Output)?;

    if pool_x.capacity().unpack() != POOL_CAPACITY || pool_y.capacity().unpack() != POOL_CAPACITY {
        return Err(Error::InvalidPoolOutCapacity);
    }

    if load_cell_data(POOL_X_INDEX, Source::Output)?.len() < SUDT_DATA_LEN
        || load_cell_data(POOL_Y_INDEX, Source::Output)?.len() < SUDT_DATA_LEN
    {
        return Err(Error::InvalidPoolOutputData);
    }

    let info_out_lock_hash = load_cell_lock_hash(INFO_INDEX, Source::Output)?;
    let pool_x_lock_hash = load_cell_lock_hash(POOL_X_INDEX, Source::Output)?;
    let pool_y_lock_hash = load_cell_lock_hash(POOL_Y_INDEX, Source::Output)?;

    if info_out_lock_hash != pool_x_lock_hash || pool_x_lock_hash != pool_y_lock_hash {
        return Err(Error::InvalidOutputLockHash);
    }

    Ok(())
}

#[allow(dead_code)]
enum HashType {
    Data,
    Code,
}

impl HashType {
    fn as_byte(&self) -> Byte {
        match self {
            HashType::Data => Byte::new(0u8),
            HashType::Code => Byte::new(1u8),
        }
    }
}
