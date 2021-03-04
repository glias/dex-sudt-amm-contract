use share::ckb_std::high_level::{load_cell_data, load_cell_lock_hash};
use share::ckb_std::{ckb_constants::Source, high_level::load_cell};

use crate::error::Error;

pub fn verify_ckb_cell(
    index: usize,
    source: Source,
    user_lock_hash: [u8; 32],
) -> Result<(), Error> {
    let ckb_cell = load_cell(index, source)?;

    if !load_cell_data(5, Source::Output)?.is_empty() {
        return Err(Error::InvalidCKBChangeData);
    }

    if ckb_cell.type_().is_some() {
        return Err(Error::InvalidCKBChangeType);
    }

    if load_cell_lock_hash(5, Source::Output)? != user_lock_hash {
        return Err(Error::InvalidCKBChangeLockHash);
    }

    Ok(())
}
