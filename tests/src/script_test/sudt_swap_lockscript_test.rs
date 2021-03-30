use super::*;

const ERR_INVALID_WITNESS_ARGS: i8 = 4;
const ERR_INVALID_SUDT_OUT_TYPE_HASH: i8 = 7;
const ERR_INVALID_SUDT_CAPACITY: i8 = 8;
const ERR_INVALID_SUDT_OUT_DATA: i8 = 9;
const ERR_INVALID_CKB_CHANGE_CAPACITY: i8 = 10;
const ERR_CKB_CHANGE_DATA_IS_NOT_EMPTY: i8 = 11;
const ERR_INVALID_CKB_CHANGE_LOCK_HASH: i8 = 13;
const ERR_SWAP_SELF: i8 = 14;
const ERR_INVALID_SWAP_REQUEST_LOCK_ARGS_MIN_AMOUNT_OUT: i8 = 15;

test_contract!(
    cancel_swap_request_success,
    {
        let swap_cell_lock_args = SwapRequestLockArgsBuilder::default()
            .user_lock_hash(user_lock_hash(5))
            .build();
        let input_0 = Inputs::new_swap(SwapRequestCell::new(SUDT_CAPACITY + 500, 100))
            .custom_lock_args(swap_cell_lock_args.as_bytes());
        let input_1 = Inputs::new_matcher(FreeCell::new(100))
            .custom_lock_args(user_lock_args(5))
            .custom_witness(witness_args_input_type(0, 0));

        let output_0 = Outputs::new_matcher(FreeCell::new(150));

        let (mut context, tx) = build_test_context(vec![input_0, input_1], vec![output_0]);
        let tx = context.complete_tx(tx);

        let cycle = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass verification");

        println!("cycle used {:?}", cycle);

        (context, tx)
    },
    true,
    "sudt-liquidity-lockscript-sim"
);

test_contract!(
    cancel_swap_request_invalid_witness_args,
    {
        let swap_cell_lock_args = SwapRequestLockArgsBuilder::default()
            .user_lock_hash(user_lock_hash(5))
            .build();
        let input_0 = Inputs::new_swap(SwapRequestCell::new(SUDT_CAPACITY + 500, 100))
            .custom_lock_args(swap_cell_lock_args.as_bytes());
        let input_1 = Inputs::new_matcher(FreeCell::new(100)).custom_lock_args(user_lock_args(5));

        let output_0 = Outputs::new_matcher(FreeCell::new(150));

        let (mut context, tx) = build_test_context(vec![input_0, input_1], vec![output_0]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_WITNESS_ARGS, 0, true, true));

        (context, tx)
    },
    true,
    "sudt-swap-lockscript-sim"
);

test_contract!(
    swap_invalid_sudt_out_data_len,
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
            .min_amount_out(15)
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
        let output_4 = Outputs::new_sudt(SudtCell::new_unchecked(SUDT_CAPACITY, rand_bytes(15)))
            .custom_type_args(pool_y_type_args)
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_OUT_DATA, 4, true, true));

        (context, tx)
    },
    true,
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
            tx_error(ERR_INVALID_CKB_CHANGE_CAPACITY, 4, true, true)
        );

        (context, tx)
    },
    true,
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
            tx_error(ERR_CKB_CHANGE_DATA_IS_NOT_EMPTY, 4, true, true)
        );

        (context, tx)
    },
    true,
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
            tx_error(ERR_INVALID_CKB_CHANGE_LOCK_HASH, 4, true, true)
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
                4,
                true,
                true
            )
        );

        (context, tx)
    },
    true,
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

        assert_error_eq!(err, tx_error(ERR_SWAP_SELF, 4, true, true));

        (context, tx)
    },
    true,
    "sudt-info-typescript-sim"
);

test_contract!(
    swap_invalid_sudt_out_cell_capacity,
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

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_CAPACITY, 4, true, true));

        (context, tx)
    },
    true,
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
            .custom_type_args(rand_bytes(32))
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(300)).custom_lock_args(user_lock_args(4));

        let (mut context, tx) =
            build_test_context(vec![input_0, input_1, input_2, input_3, input_4], vec![
                output_0, output_1, output_2, output_3, output_4, output_5,
            ]);
        let tx = context.complete_tx(tx);

        let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_OUT_TYPE_HASH, 4, true, true));

        (context, tx)
    },
    true,
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

        assert_error_eq!(err, tx_error(ERR_INVALID_SUDT_OUT_TYPE_HASH, 4, true, true));

        (context, tx)
    },
    true,
    "sudt-info-typescript-sim"
);
