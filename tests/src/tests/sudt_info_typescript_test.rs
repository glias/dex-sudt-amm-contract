use super::*;

const ERR_RANDE_END_INDEX_OUT_OF_BOUND: i8 = -1;
const ERR_INDEX_OUT_OF_BOUND: i8 = 1;
const ERR_DECODING_DATA_STRUCTURE_ERROR: i8 = 4;
const ERR_INVALID_Y_EXCHANGE_X_AMOUNT_OUT: i8 = 6;
const ERR_INVALID_X_EXCHANGE_Y_AMOUNT_OUT: i8 = 7;
const ERR_INVALID_OUTPUT_INFO_TOTAL_LIQUIDITY: i8 = 8;
const ERR_INVALID_OUTPUT_INFO_SUDT_X_RESERVE: i8 = 9;
const ERR_INVALID_OUTPUT_INFO_SUDT_Y_RESERVE: i8 = 10;
const ERR_INFO_LOCK_ARGS_FIRST_HALF_MISMATCH: i8 = 11;
const ERR_INFO_LOCK_ARGS_SECOND_HALF_MISMATCH: i8 = 12;
const ERR_INVALID_INFO_CAPACITY: i8 = 13;
const ERR_OUTPUT_MORE_THAN_ONE_INFO_CELL: i8 = 14;
const ERR_INVALID_POOL_CAPACITY: i8 = 15;
const ERR_INVALID_INFO_IN_DATA: i8 = 16;
const ERR_INVALID_OUTPUT_POOL_LOCK_HASH: i8 = 17;
const ERR_INVALID_OUTPUT_POOL_CELL_DATA: i8 = 18;
const ERR_OUTPUT_INFO_LOCK_NE_THREE: i8 = 19;
const ERR_SAME_OUTPUT_POOL_TYPE_HASH: i8 = 20;
const ERR_INVALID_POOL_X_AMOUNT: i8 = 23;
const ERR_INVALID_POOL_Y_AMOUNT: i8 = 24;
const ERR_INVALID_OUTPUT_POOL_CAPACITY: i8 = 27;
const ERR_INVALID_REQUEST_X_TYPE_HASH: i8 = 31;
const ERR_INVALID_REQUEST_Y_TYPE_HASH: i8 = 32;
const ERR_REQUEST_X_AND_Y_USER_LOCK_HASH_DIFF: i8 = 34;
const ERR_INVALID_REQUEST_LOCK_ARGS_SUDT_X_LOCK_HASH: i8 = 35;
const ERR_INVALID_REQUEST_LOCK_ARGS_AMOUNT_X_MIN_OUT: i8 = 37;
const ERR_INVALID_REQUEST_LOCK_ARGS_AMOUNT_Y_MIN_OUT: i8 = 38;
const ERR_INVALID_OUTPUT_LP_TYPE_HASH: i8 = 39;
const ERR_INVALID_OUTPUT_LP_AMOUNT: i8 = 40;
const ERR_CKB_CHANGE_DATA_IS_NOT_EMPTY: i8 = 41;
const ERR_CKB_CHANGE_TYPE_SCRIPT_IS_SOME: i8 = 42;
const ERR_INVALID_CKB_CHANGE_LOCK_HASH: i8 = 43;
const ERR_INVALID_CKB_CHANGE_CAPACITY: i8 = 44;
const ERR_INVALID_SWAP_REQUEST_TYPE_HASH: i8 = 45;
const ERR_INVALID_SWAP_REQUEST_LOCK_ARGS_SUDT_TYPE_HASH: i8 = 47;
const ERR_INVALID_SWAP_REQUEST_LOCK_ARGS_MIN_AMOUNT_OUT: i8 = 48;
const ERR_INVALID_SUDT_OUT_TYPE_HASH: i8 = 49;
const ERR_INVALID_SUDT_CAPACITY: i8 = 58;
const ERR_INVALID_SUDT_DATA_LEN: i8 = 59;
const ERR_INVALID_SUDT_LOCK_HASH: i8 = 61;
const ERR_INVALID_REMOVE_LIQUIDITY_REQUEST_CAPACITY: i8 = 65;
const ERR_INVALID_REMOVE_LIQUIDITY_REQUEST_DATA_LEN: i8 = 66;
const ERR_INVALID_REMOVE_LIQUIDITY_REQUEST_TYPE_HASH: i8 = 67;
const ERR_INVALID_OUTPUT_SUDT_X_AMOUNT: i8 = 69;
const ERR_INVALID_OUTPUT_SUDT_Y_AMOUNT: i8 = 70;

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

test_contract!(
    decode_witness_swap_cell_count,
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
        .custom_witness(witness_args_input_type_unchecked(0, 0, 6));

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
            tx_error(ERR_RANDE_END_INDEX_OUT_OF_BOUND, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    decode_witness_add_liquidity_cell_count,
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
        .custom_witness(witness_args_input_type_unchecked(0, 0, 14));

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
            tx_error(ERR_RANDE_END_INDEX_OUT_OF_BOUND, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_info_in_sudt_x_reserve_ne_zero,
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
                .sudt_x_reserve(10)
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

        assert_error_eq!(err, tx_error(ERR_INVALID_INFO_IN_DATA, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_info_in_sudt_y_reserve_ne_zero,
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
                .sudt_y_reserve(10)
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

        assert_error_eq!(err, tx_error(ERR_INVALID_INFO_IN_DATA, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_info_in_total_liquidity_ne_zero,
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
                .total_liquidity(10)
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_INFO_IN_DATA, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_request_x_type_hash,
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
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX));

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
            tx_error(ERR_INVALID_REQUEST_X_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_request_y_type_hash,
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
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX));

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
            tx_error(ERR_INVALID_REQUEST_Y_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_request_x_and_y_lock_hash_diff,
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
            .user_lock_hash(crate::tests::user_lock_hash(5))
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
            tx_error(ERR_REQUEST_X_AND_Y_USER_LOCK_HASH_DIFF, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_request_y_lock_args_x_lock_hash,
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
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(rand_bytes(137)))
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
            tx_error(
                ERR_INVALID_REQUEST_LOCK_ARGS_SUDT_X_LOCK_HASH,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_lp_out_capacity,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY - 10, 100))
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

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_lp_out_lock_hash,
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
            .custom_lock_args(user_lock_args(5));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_LOCK_HASH, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_lp_out_type_hash,
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
            .custom_type_args(rand_bytes(32))
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
            tx_error(ERR_INVALID_OUTPUT_LP_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_ckb_change_capacity,
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
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100 - 10))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_CKB_CHANGE_CAPACITY, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_ckb_change_data,
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
        let output_5 =
            Outputs::new_ckb(FreeCell::new_unchecked(SUDT_CAPACITY - 100, rand_bytes(16)))
                .custom_lock_args(user_lock_args(4));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_CKB_CHANGE_DATA_IS_NOT_EMPTY, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_ckb_change_lock_hash,
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
            .custom_lock_args(user_lock_args(5));

        let (mut context, tx) = build_test_context(
            vec![input_0, input_1, input_2, input_3, input_4, input_5],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_CKB_CHANGE_LOCK_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_output_lp_amount,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 150))
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

        assert_error_eq!(err, tx_error(ERR_INVALID_OUTPUT_LP_AMOUNT, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_info_out_sudt_x_reserve,
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
                .sudt_x_reserve(150)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 150))
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
            tx_error(ERR_INVALID_OUTPUT_INFO_SUDT_X_RESERVE, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_info_out_sudt_y_reserve,
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
                .sudt_y_reserve(150)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(POOL_X_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 150))
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
            tx_error(ERR_INVALID_OUTPUT_INFO_SUDT_Y_RESERVE, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    initial_mint_invalid_info_out_total_liquidity,
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
                .total_liquidity(150)
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
            tx_error(ERR_INVALID_OUTPUT_INFO_TOTAL_LIQUIDITY, 0, true, false)
        );

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

test_contract!(
    swap_range_index_out_of_bound,
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
        .custom_witness(witness_args_input_type(2, 0));

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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INDEX_OUT_OF_BOUND, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_requset_cell_type_hash,
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
            .custom_type_args(rand_bytes(32));

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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_SWAP_REQUEST_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_request_lock_args_sudt_type_hash,
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

        let swap_cell_lock_args = SwapRequestLockArgsBuilder::default()
            .sudt_type_hash([0u8; 32])
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(
                ERR_INVALID_SWAP_REQUEST_LOCK_ARGS_SUDT_TYPE_HASH,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_self,
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
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 138))
            .custom_type_args(pool_y_type_args.clone())
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_SUDT_OUT_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_sudt_out_cell_capacity,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY - 10, 62))
            .custom_type_args(pool_y_type_args)
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_sudt_out_type_hash,
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
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 138))
            .custom_type_args(pool_y_type_args.clone())
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_SUDT_OUT_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_ckb_change_capacity,
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
        let output_5 =
            Outputs::new_ckb(FreeCell::new(300 - 10)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_CKB_CHANGE_CAPACITY, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_ckb_change_data,
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
        let output_5 = Outputs::new_ckb(FreeCell::new_unchecked(300, rand_bytes(10)))
            .custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_CKB_CHANGE_DATA_IS_NOT_EMPTY, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_ckb_change_lock_hash,
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
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(5));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_CKB_CHANGE_LOCK_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_request_lock_args_min_amount_out,
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
            .min_amount_out(0)
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(
                ERR_INVALID_SWAP_REQUEST_LOCK_ARGS_MIN_AMOUNT_OUT,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    x_swap_y_failed,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 61))
            .custom_type_args(pool_y_type_args)
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_X_EXCHANGE_Y_AMOUNT_OUT, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    y_swap_x_failed,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 63))
            .custom_type_args(pool_x_type_args)
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_Y_EXCHANGE_X_AMOUNT_OUT, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_info_out_sudt_x_reserve,
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
                .sudt_x_reserve(200 + 90 - 10)
                .sudt_y_reserve(200 - 62)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 290 - 10))
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_INFO_SUDT_X_RESERVE, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_info_out_sudt_y_reserve,
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
                .sudt_y_reserve(200 - 62 - 10)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 290))
            .custom_type_args(pool_x_type_args)
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 138 - 10))
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_INFO_SUDT_Y_RESERVE, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_info_out_total_liquidity,
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
                .total_liquidity(100 - 10)
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_INFO_TOTAL_LIQUIDITY, 0, true, false)
        );

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

test_contract!(
    burn_liquidity_range_index_out_of_bound,
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_RANDE_END_INDEX_OUT_OF_BOUND, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_request_liquidity_cell_capacity,
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
        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY + 50, 50))
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(
                ERR_INVALID_REMOVE_LIQUIDITY_REQUEST_CAPACITY,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_liquidity_request_cell_data_len,
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
        let input_4 = Inputs::new_liquidity(LiquidityRequestCell::new_unchecked(
            2 * SUDT_CAPACITY + 50,
            rand_bytes(8),
        ))
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(
                ERR_INVALID_REMOVE_LIQUIDITY_REQUEST_DATA_LEN,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_liquidity_request_lock_args_info_type_hash,
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
            .custom_type_args(rand_bytes(32));

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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(0, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_x_out_capacity,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY - 10, 91))
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_y_capacity,
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
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY - 10, 91))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_y_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_CAPACITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_x_out_lock_hash,
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
            .custom_lock_args(user_lock_args(5))
            .custom_type_args(pool_x_type_args);
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_y_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_LOCK_HASH, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_y_out_lock_hash,
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
            .custom_lock_args(user_lock_args(5))
            .custom_type_args(pool_y_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_LOCK_HASH, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_x_out_type_hash,
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
            .custom_type_args(pool_y_type_args.clone());
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_y_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_SUDT_OUT_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_y_out_type_hash,
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
            .custom_type_args(pool_x_type_args.clone());
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_x_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_SUDT_OUT_TYPE_HASH, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_amount_x_min_out,
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
            .sudt_x_min(0)
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(
                ERR_INVALID_REQUEST_LOCK_ARGS_AMOUNT_X_MIN_OUT,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_request_lock_args_y_min_out,
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
            .sudt_y_min(0)
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(
                ERR_INVALID_REQUEST_LOCK_ARGS_AMOUNT_Y_MIN_OUT,
                0,
                true,
                false
            )
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_amount_x_out,
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
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91 + 1))
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_SUDT_X_AMOUNT, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_sudt_y_out_amount,
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
        let output_5 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 91 - 1))
            .custom_lock_args(user_lock_args(4))
            .custom_type_args(pool_y_type_args);

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_OUTPUT_SUDT_Y_AMOUNT, 0, true, false)
        );

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_info_out_sudt_x_reserve,
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
                .sudt_x_reserve(200 - 91 + 10)
                .sudt_y_reserve(200 - 91)
                .total_liquidity(100 - 45)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 109 + 10))
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

        let err = context
            .verify_tx(&tx, MAX_CYCLES)
            .unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_OUTPUT_INFO_SUDT_X_RESERVE, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_info_out_sudt_y_reserve,
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
                .sudt_y_reserve(200 - 91 - 10)
                .total_liquidity(100 - 45)
                .liquidity_sudt_type_hash(pool_cell_type_hash(POOL_X_INDEX))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 109))
            .custom_type_args(pool_x_type_args.clone())
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 109 - 10))
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

        let err = context
            .verify_tx(&tx, MAX_CYCLES)
            .unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_OUTPUT_INFO_SUDT_Y_RESERVE, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);

test_contract!(
    burn_liquidity_invalid_info_out_total_liquidity,
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
                .total_liquidity(100 - 45 - 10)
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

        let err = context
            .verify_tx(&tx, MAX_CYCLES)
            .unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_OUTPUT_INFO_TOTAL_LIQUIDITY, 0, true, false));

        (context, tx)
    },
    false,
    "sudt-info-typescript-sim"
);
