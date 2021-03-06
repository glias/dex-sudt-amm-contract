mod sudt_info_lockscript_test;
mod sudt_info_typescript_test;
mod sudt_liquidity_lockscript_test;
mod sudt_swap_lockscript_test;

use std::collections::HashMap;

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::context::Context;
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_types::bytes::Bytes;
use ckb_tool::ckb_types::packed::*;
use ckb_tool::ckb_types::prelude::*;
use ckb_x64_simulator::RunningSetup;
use molecule::prelude::*;
use rand::random;

use crate::{blake2b, test_contract, utils, Loader};
use crate::{cell_builder::*, tx_builder::*};

const INFO_INDEX: usize = 0;
const POOL_X_INDEX: usize = 1;
const POOL_Y_INDEX: usize = 2;
const MAX_CYCLES: u64 = 100_000_000;
const POOL_CAPACITY: u64 = 18_600_000_000;
const SUDT_CAPACITY: u64 = 14_200_000_000;
const INFO_CAPACITY: u64 = 25_000_000_000;

lazy_static::lazy_static! {
    static ref LIQUIDITY_SUDT_TYPE_HASH: [u8; 32] = {
        let mut ctx = Context::default();
        let args = Bytes::from(9999u64.to_le_bytes().to_vec());
        let always_success_out_point = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
        ctx.build_script(&always_success_out_point, args)
            .unwrap()
            .calc_script_hash()
            .unpack()
    };
    static ref INFO_TYPE_SCRIPT: Bytes = Loader::default().load_binary("sudt-info-type-script");
    static ref INFO_LOCK_SCRIPT: Bytes = Loader::default().load_binary("sudt-info-lock-script");
}

#[macro_export]
macro_rules! test_contract {
    ($case_name:ident, $body:expr, $is_lockscript: expr, $sim_name: expr) => {
        #[test]
        fn $case_name() {
            let (context, tx) = $body;

            let setup = RunningSetup {
                is_lock_script:  $is_lockscript,
                is_output:       false,
                script_index:    0,
                native_binaries: HashMap::default(),
            };

            write_native_setup(stringify!($case_name), $sim_name, &tx, &context, &setup);
        }
    };
}

fn sudt_type_hash(seed: usize) -> [u8; 32] {
    let mut ctx = Context::default();
    let always_success_out_point = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    ctx.build_script(&always_success_out_point, sudt_cell_type_args(seed))
        .unwrap()
        .calc_script_hash()
        .unpack()
}

fn sudt_cell_type_args(seed: usize) -> Bytes {
    Bytes::from(seed.to_le_bytes().to_vec())
}

fn pool_cell_type_args(idx: usize) -> Bytes {
    sudt_cell_type_args(idx)
}

fn pool_cell_type_hash(idx: usize) -> [u8; 32] {
    sudt_type_hash(idx)
}

fn liquidity_cell_lock_hash(args: Bytes) -> [u8; 32] {
    let mut ctx = Context::default();
    let outpoint = ctx.deploy_cell(Loader::default().load_binary("sudt-liquidity-lock-script"));
    ctx.build_script(&outpoint, args)
        .unwrap()
        .calc_script_hash()
        .unpack()
}

fn info_cell_type_hash(idx: usize) -> [u8; 32] {
    let args = info_type_args(idx);
    Script::new_builder()
        .code_hash(CellOutput::calc_data_hash(&INFO_TYPE_SCRIPT))
        .hash_type(Byte::new(0))
        .args(args.pack())
        .build()
        .calc_script_hash()
        .unpack()
}

fn info_cell_type_hash_unchecked(args: Bytes) -> [u8; 32] {
    Script::new_builder()
        .code_hash(CellOutput::calc_data_hash(&INFO_TYPE_SCRIPT))
        .hash_type(Byte::new(0))
        .args(args.pack())
        .build()
        .calc_script_hash()
        .unpack()
}

fn user_lock_hash(idx: usize) -> [u8; 32] {
    let mut ctx = Context::default();
    let always_success_out_point = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let args = Bytes::from(idx.to_le_bytes().to_vec());
    ctx.build_script(&always_success_out_point, args)
        .unwrap()
        .calc_script_hash()
        .unpack()
}

fn info_type_args(idx: usize) -> Bytes {
    let mut ctx = Context::default();
    let always_success_out_point = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let args = Bytes::from(idx.to_le_bytes().to_vec());
    ctx.build_script(&always_success_out_point, args)
        .unwrap()
        .calc_script_hash()
        .as_bytes()
}

fn liquidity_sudt_type_args() -> Bytes {
    Bytes::from(9999usize.to_le_bytes().to_vec())
}

fn user_lock_args(idx: usize) -> Bytes {
    Bytes::from(idx.to_le_bytes().to_vec())
}

fn witness_args_input_type(swap_count: u64, add_liquidity_count: u64) -> Bytes {
    let mut bytes = swap_count.to_le_bytes().to_vec();
    let mut tmp = add_liquidity_count.to_le_bytes().to_vec();
    bytes.append(&mut tmp);

    assert_eq!(bytes.len(), 16);

    let bytes_opt = Some(Bytes::from(bytes)).pack();
    WitnessArgsBuilder::default()
        .input_type(bytes_opt)
        .build()
        .as_bytes()
}

fn witness_args_input_type_unchecked(
    swap_count: u64,
    add_liquidity_count: u64,
    len: usize,
) -> Bytes {
    let mut bytes = swap_count.to_le_bytes().to_vec();
    let mut tmp = add_liquidity_count.to_le_bytes().to_vec();
    bytes.append(&mut tmp);
    bytes.truncate(len);

    let bytes_opt = Some(Bytes::from(bytes)).pack();
    WitnessArgsBuilder::default()
        .input_type(bytes_opt)
        .build()
        .as_bytes()
}

fn rand_seed(except: usize) -> usize {
    let mut ret = random::<usize>();
    while ret == except {
        ret = random::<usize>();
    }

    ret
}

fn rand_bytes(len: usize) -> Bytes {
    Bytes::from((0..len).map(|_| random::<u8>()).collect::<Vec<_>>())
}
