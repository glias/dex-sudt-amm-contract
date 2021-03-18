use core::result::Result;

use ckb_std::error::SysError as Error;

use crate::{check_args_len, decode_u128, decode_u64, decode_u8};

const LIQUIDITY_REQUEST_ARGS_LEN: usize = 137;
const MINT_LIQUIDITY_ARGS_LEN: usize = 97;
const SWAP_REQUEST_ARGS_LEN: usize = 105;
const INFO_CELL_DATA_LEN: usize = 80;
const SUDT_AMOUNT_DATA_LEN: usize = 16;

#[derive(Debug)]
pub struct LiquidityRequestLockArgs {
    pub info_type_hash: [u8; 32],
    pub user_lock_hash: [u8; 32],
    pub version:        u8,
    pub sudt_x_min:     u128,
    pub sudt_y_min:     u128,
    pub tips_ckb:       u64,
    pub tips_sudt_x:    u128,
    pub tips_sudt_y:    u128,
}

impl LiquidityRequestLockArgs {
    pub fn from_raw(cell_raw_data: &[u8]) -> Result<Self, Error> {
        check_args_len(cell_raw_data.len(), LIQUIDITY_REQUEST_ARGS_LEN)?;

        let mut info_type_hash = [0u8; 32];
        info_type_hash.copy_from_slice(&cell_raw_data[0..32]);
        let mut user_lock_hash = [0u8; 32];
        user_lock_hash.copy_from_slice(&cell_raw_data[32..64]);
        let version = decode_u8(&cell_raw_data[64..65])?;
        let sudt_x_min = decode_u128(&cell_raw_data[65..81])?;
        let sudt_y_min = decode_u128(&cell_raw_data[81..97])?;
        let tips_ckb = decode_u64(&cell_raw_data[97..105])?;
        let tips_sudt_x = decode_u128(&cell_raw_data[105..121])?;
        let tips_sudt_y = decode_u128(&cell_raw_data[121..137])?;

        Ok(LiquidityRequestLockArgs {
            info_type_hash,
            user_lock_hash,
            version,
            sudt_x_min,
            sudt_y_min,
            tips_ckb,
            tips_sudt_x,
            tips_sudt_y,
        })
    }
}

#[derive(Debug)]
pub struct MintLiquidityRequestLockArgs {
    pub info_type_hash:            [u8; 32],
    pub user_lock_hash:            [u8; 32],
    pub version:                   u8,
    pub req_sudt_x_cell_lock_hash: [u8; 32],
}

impl MintLiquidityRequestLockArgs {
    pub fn from_raw(cell_raw_data: &[u8]) -> Result<Self, Error> {
        check_args_len(cell_raw_data.len(), MINT_LIQUIDITY_ARGS_LEN)?;

        let mut info_type_hash = [0u8; 32];
        info_type_hash.copy_from_slice(&cell_raw_data[0..32]);
        let mut user_lock_hash = [0u8; 32];
        user_lock_hash.copy_from_slice(&cell_raw_data[32..64]);
        let version = decode_u8(&cell_raw_data[64..65])?;
        let mut req_sudt_x_cell_lock_hash = [0u8; 32];
        req_sudt_x_cell_lock_hash.copy_from_slice(&cell_raw_data[65..97]);

        Ok(MintLiquidityRequestLockArgs {
            info_type_hash,
            user_lock_hash,
            version,
            req_sudt_x_cell_lock_hash,
        })
    }
}

#[derive(Debug)]
pub struct SwapRequestLockArgs {
    pub sudt_type_hash: [u8; 32],
    pub user_lock_hash: [u8; 32],
    pub version:        u8,
    pub min_amount_out: u128,
    pub tips_ckb:       u64,
    pub tips_sudt:      u128,
}

impl SwapRequestLockArgs {
    pub fn from_raw(cell_raw_data: &[u8]) -> Result<Self, Error> {
        check_args_len(cell_raw_data.len(), SWAP_REQUEST_ARGS_LEN)?;

        let mut sudt_type_hash = [0u8; 32];
        sudt_type_hash.copy_from_slice(&cell_raw_data[0..32]);
        let mut user_lock_hash = [0u8; 32];
        user_lock_hash.copy_from_slice(&cell_raw_data[32..64]);
        let version = decode_u8(&cell_raw_data[64..65])?;
        let min_amount_out = decode_u128(&cell_raw_data[65..81])?;
        let tips_ckb = decode_u64(&cell_raw_data[81..89])?;
        let tips_sudt = decode_u128(&cell_raw_data[89..105])?;

        Ok(SwapRequestLockArgs {
            sudt_type_hash,
            user_lock_hash,
            version,
            min_amount_out,
            tips_ckb,
            tips_sudt,
        })
    }
}

#[derive(Debug)]
pub struct InfoCellData {
    pub sudt_x_reserve:           u128,
    pub sudt_y_reserve:           u128,
    pub total_liquidity:          u128,
    pub liquidity_sudt_type_hash: [u8; 32],
}

impl InfoCellData {
    pub fn from_raw(cell_raw_data: &[u8]) -> Result<InfoCellData, Error> {
        check_args_len(cell_raw_data.len(), INFO_CELL_DATA_LEN)?;

        let sudt_x_reserve = decode_u128(&cell_raw_data[0..16])?;
        let sudt_y_reserve = decode_u128(&cell_raw_data[16..32])?;
        let total_liquidity = decode_u128(&cell_raw_data[32..48])?;
        let mut liquidity_sudt_type_hash = [0u8; 32];
        liquidity_sudt_type_hash.copy_from_slice(&cell_raw_data[48..80]);

        Ok(InfoCellData {
            sudt_x_reserve,
            sudt_y_reserve,
            total_liquidity,
            liquidity_sudt_type_hash,
        })
    }
}

#[derive(Debug)]
pub struct SUDTAmountData {
    pub sudt_amount: u128,
}

impl SUDTAmountData {
    pub fn from_raw(cell_raw_data: &[u8]) -> Result<Self, Error> {
        check_args_len(cell_raw_data.len(), SUDT_AMOUNT_DATA_LEN)?;
        let sudt_amount = decode_u128(&cell_raw_data[0..16])?;

        Ok(SUDTAmountData { sudt_amount })
    }
}
