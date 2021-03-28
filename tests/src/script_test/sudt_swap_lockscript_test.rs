use super::*;

const ERR_INVALID_WITNESS_ARGS: i8 = 4;

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
