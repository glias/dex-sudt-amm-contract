use ckb_tool::ckb_types::core::Capacity;
use ckb_tool::ckb_types::packed::Uint128;
use ckb_tool::ckb_types::{bytes::Bytes, prelude::*};

use crate::schema::cell::{
    InfoCellData, LiquidityRequestLockArgs, MintLiquidityRequestLockArgs, SwapRequestLockArgs,
};

pub struct InfoCell {
    pub capacity: Capacity,
    pub data:     Bytes,
}

impl InfoCell {
    pub fn new_unchecked(capacity: u64, data: Bytes) -> Self {
        InfoCell {
            capacity: Capacity::shannons(capacity),
            data,
        }
    }

    pub fn custom_capacity(mut self, capacity: u64) -> Self {
        self.capacity = Capacity::shannons(capacity);
        self
    }
}

#[derive(Default)]
pub struct LiquidityRequestCell {
    pub capacity: Capacity,
    pub data:     Bytes,
}

impl LiquidityRequestCell {
    pub fn new(capacity: u64, amount: u128) -> Self {
        let sudt_data: Uint128 = amount.pack();

        LiquidityRequestCell {
            capacity: Capacity::shannons(capacity),
            data:     sudt_data.as_bytes(),
        }
    }

    pub fn new_unchecked(capacity: u64, data: Bytes) -> Self {
        LiquidityRequestCell {
            capacity: Capacity::shannons(capacity),
            data,
        }
    }
}

#[derive(Default)]
pub struct MintLiquidityRequestCell {
    pub capacity: Capacity,
    pub data:     Bytes,
}

impl MintLiquidityRequestCell {
    pub fn new(capacity: u64, amount: u128) -> Self {
        let sudt_data: Uint128 = amount.pack();

        MintLiquidityRequestCell {
            capacity: Capacity::shannons(capacity),
            data:     sudt_data.as_bytes(),
        }
    }

    pub fn new_unchecked(capacity: u64, data: Bytes) -> Self {
        MintLiquidityRequestCell {
            capacity: Capacity::shannons(capacity),
            data,
        }
    }
}

#[derive(Default)]
pub struct SwapRequestCell {
    pub capacity: Capacity,
    pub data:     Bytes,
}

impl SwapRequestCell {
    pub fn new(capacity: u64, amount: u128) -> Self {
        let sudt_data: Uint128 = amount.pack();

        SwapRequestCell {
            capacity: Capacity::shannons(capacity),
            data:     sudt_data.as_bytes(),
        }
    }

    pub fn new_unchecked(capacity: u64, data: Bytes) -> Self {
        SwapRequestCell {
            capacity: Capacity::shannons(capacity),
            data,
        }
    }
}

#[derive(Default)]
pub struct LiquidityRequestLockArgsBuilder {
    info_type_hash: [u8; 32],
    user_lock_hash: [u8; 32],
    version:        u8,
    sudt_x_min:     u128,
    sudt_y_min:     u128,
    tips_ckb:       u64,
    tips_sudt_x:    u128,
    tips_sudt_y:    u128,
}

impl LiquidityRequestLockArgsBuilder {
    pub fn user_lock_hash(mut self, user_lock_hash: [u8; 32]) -> Self {
        self.user_lock_hash = user_lock_hash;
        self
    }

    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    pub fn sudt_x_min(mut self, sudt_x_min: u128) -> Self {
        self.sudt_x_min = sudt_x_min;
        self
    }

    pub fn sudt_y_min(mut self, sudt_y_min: u128) -> Self {
        self.sudt_y_min = sudt_y_min;
        self
    }

    pub fn info_type_hash(mut self, info_type_hash: [u8; 32]) -> Self {
        self.info_type_hash = info_type_hash;
        self
    }

    pub fn tips_ckb(mut self, tips_ckb: u64) -> Self {
        self.tips_ckb = tips_ckb;
        self
    }

    pub fn tips_sudt_x(mut self, tips_sudt_x: u128) -> Self {
        self.tips_sudt_x = tips_sudt_x;
        self
    }

    pub fn tips_sudt_y(mut self, tips_sudt_y: u128) -> Self {
        self.tips_sudt_y = tips_sudt_y;
        self
    }

    pub fn build(self) -> LiquidityRequestLockArgs {
        LiquidityRequestLockArgs::new_builder()
            .info_type_hash(self.info_type_hash.pack())
            .user_lock_hash(self.user_lock_hash.pack())
            .version(self.version.pack())
            .sudt_x_min(self.sudt_x_min.pack())
            .sudt_y_min(self.sudt_y_min.pack())
            .tips_ckb(self.tips_ckb.pack())
            .tips_sudt_x(self.tips_sudt_x.pack())
            .tips_sudt_y(self.tips_sudt_y.pack())
            .build()
    }
}

#[derive(Default)]
pub struct MintLiquidityRequestLockArgsBuilder {
    info_type_hash:            [u8; 32],
    user_lock_hash:            [u8; 32],
    version:                   u8,
    req_sudt_x_cell_lock_hash: [u8; 32],
}

impl MintLiquidityRequestLockArgsBuilder {
    pub fn info_type_hash(mut self, info_type_hash: [u8; 32]) -> Self {
        self.info_type_hash = info_type_hash;
        self
    }

    pub fn user_lock_hash(mut self, user_lock_hash: [u8; 32]) -> Self {
        self.user_lock_hash = user_lock_hash;
        self
    }

    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    pub fn req_sudt_x_cell_lock_hash(mut self, req_sudt_x_cell_lock_hash: [u8; 32]) -> Self {
        self.req_sudt_x_cell_lock_hash = req_sudt_x_cell_lock_hash;
        self
    }

    pub fn build(self) -> MintLiquidityRequestLockArgs {
        MintLiquidityRequestLockArgs::new_builder()
            .user_lock_hash(self.user_lock_hash.pack())
            .info_type_hash(self.info_type_hash.pack())
            .version(self.version.pack())
            .req_sudt_x_cell_lock_hash(self.req_sudt_x_cell_lock_hash.pack())
            .build()
    }
}

#[derive(Default)]
pub struct SwapRequestLockArgsBuilder {
    sudt_type_hash: [u8; 32],
    user_lock_hash: [u8; 32],
    version:        u8,
    min_amount_out: u128,
    tips_ckb:       u64,
    tips_sudt:      u128,
}

impl SwapRequestLockArgsBuilder {
    pub fn user_lock_hash(mut self, user_lock_hash: [u8; 32]) -> Self {
        self.user_lock_hash = user_lock_hash;
        self
    }

    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    pub fn min_amount_out(mut self, min_amount_out: u128) -> Self {
        self.min_amount_out = min_amount_out;
        self
    }

    pub fn sudt_type_hash(mut self, sudt_type_hash: [u8; 32]) -> Self {
        self.sudt_type_hash = sudt_type_hash;
        self
    }

    pub fn tips_ckb(mut self, tips_ckb: u64) -> Self {
        self.tips_ckb = tips_ckb;
        self
    }

    pub fn tips_sudt(mut self, tips_sudt: u128) -> Self {
        self.tips_sudt = tips_sudt;
        self
    }

    pub fn build(self) -> SwapRequestLockArgs {
        SwapRequestLockArgs::new_builder()
            .user_lock_hash(self.user_lock_hash.pack())
            .version(self.version.pack())
            .min_amount_out(self.min_amount_out.pack())
            .sudt_type_hash(self.sudt_type_hash.pack())
            .tips_ckb(self.tips_ckb.pack())
            .tips_sudt(self.tips_sudt.pack())
            .build()
    }
}

#[derive(Default)]
pub struct InfoCellBuilder {
    capacity:                 u64,
    sudt_x_reserve:           u128,
    sudt_y_reserve:           u128,
    total_liquidity:          u128,
    liquidity_sudt_type_hash: [u8; 32],
}

impl InfoCellBuilder {
    pub fn capacity(mut self, capacity: u64) -> Self {
        self.capacity = capacity;
        self
    }

    pub fn sudt_x_reserve(mut self, sudt_x_reserve: u128) -> Self {
        self.sudt_x_reserve = sudt_x_reserve;
        self
    }

    pub fn sudt_y_reserve(mut self, sudt_y_reserve: u128) -> Self {
        self.sudt_y_reserve = sudt_y_reserve;
        self
    }

    pub fn total_liquidity(mut self, total_liquidity: u128) -> Self {
        self.total_liquidity = total_liquidity;
        self
    }

    pub fn liquidity_sudt_type_hash(mut self, liquidity_sudt_type_hash: [u8; 32]) -> Self {
        self.liquidity_sudt_type_hash = liquidity_sudt_type_hash;
        self
    }

    pub fn build(self) -> InfoCell {
        let info_data = InfoCellData::new_builder()
            .sudt_x_reserve(self.sudt_x_reserve.pack())
            .sudt_y_reserve(self.sudt_y_reserve.pack())
            .total_liquidity(self.total_liquidity.pack())
            .liquidity_sudt_type_hash(self.liquidity_sudt_type_hash.pack())
            .build();

        InfoCell {
            capacity: Capacity::shannons(self.capacity),
            data:     info_data.as_bytes(),
        }
    }
}

pub struct SudtCell {
    pub capacity: Capacity,
    pub data:     Bytes,
}

impl SudtCell {
    pub fn new(capacity: u64, amount: u128) -> Self {
        let sudt_data: Uint128 = amount.pack();

        SudtCell {
            capacity: Capacity::shannons(capacity),
            data:     sudt_data.as_bytes(),
        }
    }

    pub fn new_unchecked(capacity: u64, data: Bytes) -> Self {
        SudtCell {
            capacity: Capacity::shannons(capacity),
            data,
        }
    }
}

pub struct FreeCell {
    pub capacity: Capacity,
    pub data:     Bytes,
}

impl FreeCell {
    pub fn new(capacity: u64) -> Self {
        FreeCell {
            capacity: Capacity::shannons(capacity),
            data:     Bytes::new(),
        }
    }

    pub fn new_unchecked(capacity: u64, data: Bytes) -> Self {
        FreeCell {
            capacity: Capacity::shannons(capacity),
            data,
        }
    }
}
