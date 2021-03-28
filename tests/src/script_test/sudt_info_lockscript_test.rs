use super::*;

const ERR_INVALID_INPUT_INFO_LOCK_COUNT: i8 = 6;
const ERR_INVALID_INFO_LOCK_ARGS_POOL_HASH: i8 = 7;
const ERR_INVALID_INFO_LOCK_ARGS_INFO_TYPE_HASH: i8 = 8;

test_contract!(
    invalid_info_args_pool_hash,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        hash.reverse();
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_INFO_LOCK_ARGS_POOL_HASH, 0, true, true)
        );

        (context, tx)
    },
    true,
    "sudt-info-lockscript-sim"
);

test_contract!(
    invalid_info_args_info_type_hash,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        let mut hash_1 = info_cell_type_hash(0).to_vec();
        hash_1.reverse();
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

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_INFO_LOCK_ARGS_INFO_TYPE_HASH, 0, true, true)
        );

        (context, tx)
    },
    true,
    "sudt-info-lockscript-sim"
);

test_contract!(
    invalid_pool_cell_count,
    {
        let pool_x_type_hash = pool_cell_type_hash(POOL_X_INDEX);
        let pool_y_type_hash = pool_cell_type_hash(POOL_Y_INDEX);
        let mut hash = blake2b!(pool_x_type_hash, pool_y_type_hash).to_vec();
        hash.reverse();
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

        let input_6 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(POOL_Y_INDEX))
            .custom_lock_args(Bytes::from(hash.clone()));

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
            vec![
                input_0, input_1, input_2, input_3, input_4, input_5, input_6,
            ],
            vec![output_0, output_1, output_2, output_3, output_4, output_5],
        );
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(
            err,
            tx_error(ERR_INVALID_INPUT_INFO_LOCK_COUNT, 0, true, true)
        );

        (context, tx)
    },
    true,
    "sudt-info-lockscript-sim"
);
