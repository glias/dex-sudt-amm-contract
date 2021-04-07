# dex-sudt-amm-contract

The Glias DEX AMM contract with SUDT and another SUDT pair.

## Pre-requirment

* [capsule](https://github.com/nervosnetwork/capsule) >= 0.4.4
* [ckb-cli](https://github.com/nervosnetwork/ckb-cli) >= 0.39.0

> Note: Capsule uses docker to build contracts and run tests. https://docs.docker.com/get-docker/
> and docker and ckb-cli must be accessible in the PATH in order for them to be used by Capsule.

## Getting Start

* Build contract

```shell
capsule build --release
```

* Run tests

```shell
make schema
make test
```

## Transaction View

### Create Pool

```
                                 info_cell
any_free_ckb_cell    ------->    pool_x_cell
                                 pool_y_cell
                                 change_cell
```

### Initial Mint Liquidity

```
info_in_cell                info_out_cell
pool_x_in_cell              pool_x_out_cell
pool_y_in_cell              pool_y_out_cell
                ------->
matcher_in_cell             matcher_out_cell
req_sudt_x_cell             sudt_lp_cell
req_sudt_y_cell             ckb_change_cell
```

### Swap And Liquidity Transaction

```
info_in_cell                            info_out_cell
pool_x_in_cell                          pool_x_out_cell
pool_y_in_cell                          pool_y_out_cell
                          ------->
matcher_in_cell                         matcher_out_ckb_cell

[swap_request_cell]                     [sudt_swapped_cell
                                       + ckb_change_cell]

[ add_liquidity_x_cell                  [sudt_lp_cell
+ add_liquidity_y_cell]                 + sudt_change_cell
                                       + ckb_change_cell]

[remove_liquidity_cell]                 [sudt_x_cell
                                       + sudt_y_cell]
```

> Notice that the witness argument of index zero in inputs should contain the count of swap request cell and the count of mint liquidity cell count. The two counts should be encoded into little-endian byte arrays and concat join them. It should be saved in the `input_type` field, except create pool transaction.

##  Deployment

### 1. Update the deployment configurations

Open `deployment.toml` :

- cells describes which cells to be deployed.

  - `name`: Define the reference name used in the deployment configuration.
  - `enable_type_id` : If it is set to true means create a type_id for the cell.
  - `location` : Define the script binary path.
  - `dep_groups` describes which dep_groups to be created. Dep Group is a cell which bundles several cells as its members. When a dep group cell is used in cell_deps, it has the same effect as adding all its members into cell_deps. In our case, we don’t need dep_groups.

- `lock` describes the lock field of the new deployed cells.It is recommended to set lock to the address(an address that you can unlock) of deployer in the dev chain and in the testnet, which is easier to update the script.

### 2. Build release version of the script

The release version of script doesn’t include debug symbols which makes the size smaller.

```shell
capsule build --release
```

#### 3. Deploy the script

```shell
capsule deploy --address <ckt1....> --fee 0.001
```

If the `ckb-cli` has been installed and `dev-chain` RPC is connectable, you will see the deployment plan:

new_occupied_capacity and total_occupied_capacity refer how much CKB to store cells and data.
txs_fee_capacity refers how much CKB to pay the transaction fee.

### 4. Type yes or y and input the password to unlock the account.

```shell
send cell_tx 0xcdfd397823f6a130294c72fbe397c469d459b83db401296c291db7b170b15839
Deployment complete
```

Now the dex script has been deployed, you can refer to this script by using `tx_hash: 0xcdfd397823f6a130294c72fbe397c469d459b83db401296c291db7b170b15839 index: 0` as `out_point`(your tx_hash should be another value).
