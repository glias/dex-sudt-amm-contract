SCHEMA_PATH := schemas
SCHEMA_DEST_PATH := src/schema/generated

schema:
	moleculec --language rust --schema-file ${SCHEMA_PATH}/basic.mol > ${SCHEMA_DEST_PATH}/basic.rs
	moleculec --language rust --schema-file ${SCHEMA_PATH}/cell.mol > ${SCHEMA_DEST_PATH}/cell.rs