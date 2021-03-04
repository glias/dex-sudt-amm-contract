use share::ckb_std::error::SysError;
use share::error::HelperError;

/// Error
#[repr(i8)]
#[derive(Debug)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    MissingTypeScript = 5,
    YExchangeXFailed,
    XExchangeYFailed,
    InvalidTotalLiquidity,
    InvalidSUDTXReserve,
    InvalidSUDTYReserve = 10,
    PoolTypeHashMismatch,
    InfoTypeHashMismatch,
    InfoCapacityDiff,
    MoreThanOneInfoCell,
    InvalidPoolInCapacity = 15,
    InvalidInfoInData,
    InvalidOutputLockHash,
    InvalidPoolOutputData,
    NoInfoCellInDeps,
    SameSUDTInPair = 20,
    InvalidLockScriptHashType,
    InvalidInfoCellDepsCount,
    PoolXAmountDiff,
    PoolYAmountDiff,
    InfoCellTypeHashDiff = 25,
    InfoCellLockHashDiff,
    InvalidPoolOutCapacity,
    InvalidPoolInLockHash,
    PoolCellTypeHashDiff,
    PoolCellLockHashDiff = 30,
    InvalidSUDTXTypeHash,
    InvalidSUDTYTypeHash,
    InvalidLiquidityReqLockArgsInfoTypeHash,
    UserLockHashDiff,
    InvalidReqSUDTXLockHash = 35,
    InvalidLpCapacity,
    InvalidLpDataLen,
    InvalidLpLockHash,
    InvalidLpTypeHash,
    InvalidLpAmount = 40,
    InvalidCKBChangeData,
    InvalidCKBChangeType,
    InvalidCKBChangeLockHash,
    InvalidCKBChangeCapacity,
    InvalidSwapReqTypeHash = 45,
    InvalidSwapReqDataLen,
    InvalidSwapReqLockArgsTypeHash,
    InvalidSwapReqLockArgsMinAmount,
    InvalidSUDTOutTypeHash,
    TotalLiquidityIsZero = 50,
    InvalidLiquidityReqXTypeHash,
    InvalidLiquidityReqYTypeHash,
    InvalidLiquidityReqXDataLen,
    InvalidLiquidityReqYDataLen,
    InvalidLiquidityReqXLockHash = 55,
    InvalidLiquidityReqYLockHash,
    InvalidLiquidityReqYLockArgsXLockHash,
    InvalidSUDTCapacity,
    InvalidSUDTDataLen,
    InvalidSUDTChangeTypeHash = 60,
    InvalidSUDTLockHash,
    InvalidXAmountMin,
    InvalidYAmountMin,
    InvalidLiquidityAmount,
    InvalidRemoveLpCapacity = 65,
    InvalidRemoveLpDataLen,
    InvalidRemoveLpTypeHash,
    InvalidRemoveLpLockHash,
    InvalidXAmountOut,
    InvalidYAmountOut = 70,
    InvalidXAmountOutMin,
    InvalidYAmountOutMin,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

impl From<HelperError> for Error {
    fn from(err: HelperError) -> Self {
        match err {
            HelperError::MissingTypeScript => Self::MissingTypeScript,
        }
    }
}
