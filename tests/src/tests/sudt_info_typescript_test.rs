use super::*;

// #####################
// Initial Mint Tests
// #####################
test_contract!(
    sudt_change_ckb_initial_mint_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(1);
        let pool_y_type_hash = pool_cell_type_hash(2);
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
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(2))
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
            .custom_type_args(pool_cell_type_args(1));

        let req_y_lock_args = MintLiquidityRequestLockArgsBuilder::default()
            .info_type_hash(info_cell_type_hash(0))
            .req_sudt_x_cell_lock_hash(liquidity_cell_lock_hash(req_x_lock_args.as_bytes()))
            .user_lock_hash(user_lock_hash)
            .build();
        let input_5 = Inputs::new_liquidity(LiquidityRequestCell::new(SUDT_CAPACITY, 100))
            .custom_lock_args(req_y_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(2));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(1))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(2))
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

// #####################
// Swap Tests
// #####################

test_contract!(
    change_ckb_initial_mint_success,
    {
        let pool_x_type_hash = pool_cell_type_hash(1);
        let pool_y_type_hash = pool_cell_type_hash(1);
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
        .custom_witness(witness_args_input_type(1, 0));

        let input_1 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(Bytes::from(hash.clone()));
        let input_2 = Inputs::new_pool(SudtCell::new(POOL_CAPACITY, 0))
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(Bytes::from(hash.clone()));

        let input_3 = Inputs::new_matcher(FreeCell::new(100));

        let sudt_type_hash = sudt_type_hash(random::<usize>());
        let swap_cell_lock_args = SwapRequestLockArgsBuilder::default()
            .sudt_type_hash(sudt_type_hash)
            .user_lock_hash(user_lock_hash(4))
            .build();
        let input_4 = Inputs::new_swap(SwapRequestCell::new(100, 100))
            .custom_lock_args(swap_cell_lock_args.as_bytes())
            .custom_type_args(pool_cell_type_args(1));

        let output_0 = Outputs::new_info(
            InfoCellBuilder::default()
                .capacity(INFO_CAPACITY)
                .sudt_x_reserve(100)
                .sudt_y_reserve(100)
                .total_liquidity(100)
                .liquidity_sudt_type_hash(pool_cell_type_hash(1))
                .build(),
        )
        .custom_lock_args(Bytes::from(hash.clone()));
        let output_1 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(Bytes::from(hash.clone()));
        let output_2 = Outputs::new_pool(SudtCell::new(POOL_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(Bytes::from(hash));

        let output_3 = Outputs::new_matcher(FreeCell::new(150));
        let output_4 = Outputs::new_sudt(SudtCell::new(SUDT_CAPACITY, 100))
            .custom_type_args(pool_cell_type_args(1))
            .custom_lock_args(user_lock_args(4));
        let output_5 = Outputs::new_ckb(FreeCell::new(SUDT_CAPACITY - 100))
            .custom_lock_args(user_lock_args(4));

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


