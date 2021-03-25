use super::*;

const ERR_DECODING_DATA_STRUCTURE_ERROR: i8 = 4;
const ERR_INFO_LOCK_ARGS_FIRST_HALF_MISMATCH: i8 = 11;
const ERR_INFO_LOCK_ARGS_SECOND_HALF_MISMATCH: i8 = 12;
const ERR_INVALID_INFO_CAPACITY: i8 = 13;
const ERR_OUTPUT_MORE_THAN_ONE_INFO_CELL: i8 = 14;
const ERR_INVALID_POOL_CAPACITY: i8 = 15;
const ERR_INVALID_OUTPUT_POOL_LOCK_HASH: i8 = 17;
const ERR_INVALID_OUTPUT_POOL_CELL_DATA: i8 = 18;
const ERR_OUTPUT_INFO_LOCK_NE_THREE: i8 = 19;
const ERR_SAME_OUTPUT_POOL_TYPE_HASH: i8 = 20;
const ERR_INVALID_POOL_X_AMOUNT: i8 = 23;
const ERR_INVALID_POOL_Y_AMOUNT: i8 = 24;
const ERR_INVALID_OUTPUT_POOL_CAPACITY: i8 = 27;

// #####################
// Create Info Tests
// #####################
test_contract!(
    info_creation_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_info_lock_ne_three,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_OUTPUT_INFO_LOCK_NE_THREE, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_same_pool_type_hash,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_SAME_OUTPUT_POOL_TYPE_HASH, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_info_lock_args_first_half_mismatch,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        hash.reverse();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INFO_LOCK_ARGS_FIRST_HALF_MISMATCH, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_info_lock_args_second_half_mismatch,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash_1.reverse();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INFO_LOCK_ARGS_SECOND_HALF_MISMATCH, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_pool_x_capacity_err,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY - 10, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_POOL_CAPACITY, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_pool_y_capacity_err,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY - 10, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_POOL_CAPACITY, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_pool_x_data_err,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new_unchecked(POOL_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_POOL_CELL_DATA, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_pool_y_data_err,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new_unchecked(POOL_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_POOL_CELL_DATA, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_invalid_pool_x_lock_hash,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(rand_bytes(64));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_POOL_LOCK_HASH, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    info_creation_invalid_pool_y_lock_hash,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_matcher(FreeCell::new(SUDT_CAPACITY));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(rand_bytes(64));

        let output_3 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0], vec![output_0, output_1, output_2, output_3]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_POOL_LOCK_HASH, 0, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

// #####################
// Initial Mint Tests
// #####################
test_contract!(
    sudt_change_sudt_initial_mint_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    ckb_change_sudt_initial_mint_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    output_more_than_one_info_cell,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let output_6 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![
                output_0, output_1, output_2, output_3, output_4, output_5, output_6,
            ],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_OUTPUT_MORE_THAN_ONE_INFO_CELL, 6, false, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_info_in_data,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(InfoCell::new_unchecked(INFO_CAPACITY, rand_bytes(79)))
            .custom_lock_args(Bytes::from(hash.clone()))
            .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_DECODING_DATA_STRUCTURE_ERROR, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_info_out_data,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(InfoCell::new_unchecked(INFO_CAPACITY, rand_bytes(79)))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_DECODING_DATA_STRUCTURE_ERROR, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_pool_x_in_data,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new_unchecked(POOL_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_DECODING_DATA_STRUCTURE_ERROR, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_pool_y_in_data,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new_unchecked(POOL_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_DECODING_DATA_STRUCTURE_ERROR, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_pool_x_out_data,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new_unchecked(POOL_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_DECODING_DATA_STRUCTURE_ERROR, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_pool_y_out_data,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new_unchecked(POOL_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_DECODING_DATA_STRUCTURE_ERROR, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_info_out_capcacity,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build()
                .custom_capacity(INFO_CAPACITY - 10),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_INFO_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_x_in_amount,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 10))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_X_AMOUNT, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_y_in_amount,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 10))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_Y_AMOUNT, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_x_out_amount,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 1100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_X_AMOUNT, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_y_out_amount,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 1100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_Y_AMOUNT, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_x_in_capacity,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY + 10, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_y_in_capacity,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY + 10, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_x_out_capacity,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY + 10, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    invalid_pool_y_out_capacity,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let user_lock_hash = user_lock_hash(4);
        let req_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash)
            .tips_ckb(100)
            .build();

        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_x_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(INFO_INDEX))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY + 10, 100))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(liquidity_sudt_type_args())
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_POOL_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

// #####################
// Swap Tests
// #####################
test_contract!(
    x_swap_y_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .sudt_x_reserve(200)
                .sudt_y_reserve(200)
                .total_liquidity(100)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(1, 0));

        let pool_x_type_args = pool_cell_type_args(POOL_X_INDEX);
        let pool_y_type_args = pool_cell_type_args(POOL_Y_INDEX);

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let sudt_type_hash = pool_y_type_hash;
        let swap_cell_lock_args = SwapRequestLockArgsBuilder::default()
            .sudt_type_hash(sudt_type_hash)
            .user_lock_hash(user_lock_hash(4))
            .tips_sudt(10)
            .tips_ckb(200)
            .min_amount_out(50)
            .build();
        let input_4 = Inputs::new_swap(SwapRequestCell::new(SUDT_CAPACITY + 500, 100))
            .custom_lock_args(swap_cell_lock_args.as_bytes())
            .custom_type_args(pool_x_type_args.clone());

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(200 + 90)
                .sudt_y_reserve(200 - 62)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 290))
            .custom_type_args(pool_x_type_args)
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 138))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 62))
            .custom_type_args(pool_y_type_args)
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    y_swap_x_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .sudt_x_reserve(200)
                .sudt_y_reserve(200)
                .total_liquidity(100)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(1, 0));

        let pool_x_type_args = pool_cell_type_args(POOL_X_INDEX);
        let pool_y_type_args = pool_cell_type_args(POOL_Y_INDEX);

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let sudt_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let swap_cell_lock_args = SwapRequestLockArgsBuilder::default()
            .sudt_type_hash(sudt_type_hash)
            .user_lock_hash(user_lock_hash(4))
            .tips_sudt(10)
            .tips_ckb(200)
            .min_amount_out(50)
            .build();
        let input_4 = Inputs::new_swap(SwapRequestCell::new(SUDT_CAPACITY + 500, 100))
            .custom_lock_args(swap_cell_lock_args.as_bytes())
            .custom_type_args(pool_y_type_args.clone());

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(200 - 62)
                .sudt_y_reserve(200 + 90)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 138))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 290))
            .custom_type_args(pool_y_type_args)
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 62))
            .custom_type_args(pool_x_type_args)
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

// #####################
// Mint Liquidity Tests
// #####################
test_contract!(
    mint_liquidity_x_exhausted_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .sudt_x_reserve(200)
                .sudt_y_reserve(200)
                .total_liquidity(100)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 1));

        let pool_x_type_args = pool_cell_type_args(POOL_X_INDEX);
        let pool_y_type_args = pool_cell_type_args(POOL_Y_INDEX);

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let liquidity_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .user_lock_hash(user_lock_hash(4))
            .info_type_hash(info_cell_type_hash(0))
            .sudt_x_min(15)
            .sudt_y_min(15)
            .tips_sudt_x(5)
            .tips_sudt_y(5)
            .tips_ckb(10)
            .build();
        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY + 50, 100))
            .custom_lock_args(liquidity_x_lock_args.as_bytes())
            .custom_type_args(pool_x_type_args.clone());

        let liquidity_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash(4))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(liquidity_x_lock_args.as_bytes()))
            .build();
        let input_5 =
            Inputs::new_mint_liquidity(MintLiquidityRequestCell::new(SUDT_CAPACITY + 50, 110))
                .custom_lock_args(liquidity_y_lock_args.as_bytes())
                .custom_type_args(pool_y_type_args.clone());

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(200 + 95)
                .sudt_y_reserve(200 + 96)
                .total_liquidity(100 + 48)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 295))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 296))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 48))
            .custom_type_args(liquidity_sudt_type_args());
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 9))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_y_type_args);
        let output_6 = Outputs::new_ckb(FreeCell::new(90)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![
                output_0, output_1, output_2, output_3, output_4, output_5, output_6,
            ],
        );
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    mint_liquidity_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .sudt_x_reserve(200)
                .sudt_y_reserve(200)
                .total_liquidity(100)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 1));

        let pool_x_type_args = pool_cell_type_args(POOL_X_INDEX);
        let pool_y_type_args = pool_cell_type_args(POOL_Y_INDEX);

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let liquidity_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .user_lock_hash(user_lock_hash(4))
            .info_type_hash(info_cell_type_hash(0))
            .sudt_x_min(15)
            .sudt_y_min(15)
            .tips_sudt_x(5)
            .tips_sudt_y(5)
            .tips_ckb(10)
            .build();
        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY + 50, 110))
            .custom_lock_args(liquidity_x_lock_args.as_bytes())
            .custom_type_args(pool_x_type_args.clone());

        let liquidity_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .user_lock_hash(user_lock_hash(4))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(liquidity_x_lock_args.as_bytes()))
            .build();
        let input_5 =
            Inputs::new_mint_liquidity(MintLiquidityRequestCell::new(SUDT_CAPACITY + 50, 100))
                .custom_lock_args(liquidity_y_lock_args.as_bytes())
                .custom_type_args(pool_y_type_args.clone());

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(200 + 96)
                .sudt_y_reserve(200 + 95)
                .total_liquidity(100 + 48)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 296))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 295))
            .custom_type_args(pool_y_type_args)
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 48))
            .custom_type_args(liquidity_sudt_type_args());
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 9))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_x_type_args);
        let output_6 = Outputs::new_ckb(FreeCell::new(90)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![
                output_0, output_1, output_2, output_3, output_4, output_5, output_6,
            ],
        );
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

// #####################
// Burn Liquidity Tests
// #####################
test_contract!(
    burn_liquidity_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash.append(&mut hash_1);
        assert_eq!(hash.len(), 64);

        let input_0 = Inputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .liquidity_sudt_type_hash(*LIQUIDITY_SUDT_TYPE_HASH)
                .sudt_x_reserve(200)
                .sudt_y_reserve(200)
                .total_liquidity(100)
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()))
        .custom_witness(witness_args_input_type(0, 0));

        let pool_x_type_args = pool_cell_type_args(POOL_X_INDEX);
        let pool_y_type_args = pool_cell_type_args(POOL_Y_INDEX);

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 200))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let liquidity_x_lock_args = LiquidityRequestLockArgsBuilder::default()
            .user_lock_hash(user_lock_hash(4))
            .info_type_hash(info_cell_type_hash(0))
            .sudt_x_min(15)
            .sudt_y_min(15)
            .tips_sudt_x(5)
            .tips_ckb(10)
            .build();
        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(2 * SUDT_CAPACITY + 50, 50))
            .custom_lock_args(liquidity_x_lock_args.as_bytes())
            .custom_type_args(liquidity_sudt_type_args());

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(200 - 91)
                .sudt_y_reserve(200 - 91)
                .total_liquidity(100 - 45)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 109))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 109))
            .custom_type_args(pool_y_type_args.clone())
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_x_type_args);
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_y_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);
