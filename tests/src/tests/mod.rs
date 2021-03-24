mod sudt_info_typescript_test;

use std::collections::HashMap;

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::context::Context;
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_types::bytes::Bytes;
use ckb_tool::ckb_types::packed::*;
use ckb_tool::ckb_types::prelude::*;
use ckb_x64_simulator::RunningSetup;
use molecule::prelude::*;

use crate::{blake2b, test_contract, utils, Loader};
use crate::{cell_builder::*, tx_builder::*};

const MAX_CYCLES: u64 = 10000_0000;
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

fn pool_cell_type_hash(idx: usize) -> [u8; 32] {
    let mut ctx = Context::default();
    let always_success_out_point = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    ctx.build_script(&always_success_out_point, pool_cell_type_args(idx))
        .unwrap()
        .calc_script_hash()
        .unpack()
}

fn pool_cell_type_args(idx: usize) -> Bytes {
    Bytes::from(idx.to_le_bytes().to_vec())
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
    let mut tmp = add_liquidity_count.to_be_bytes().to_vec();
    bytes.append(&mut tmp);

    let bytes_opt = Some(Bytes::from(bytes)).pack();
    WitnessArgsBuilder::default()
        .input_type(bytes_opt)
        .build()
        .as_bytes()
}
