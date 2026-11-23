-- Existing rows have no trustworthy history of the last complete report.
-- Do not infer success timestamps from a recent failed attempt or old row data.
ALTER TABLE t_asset_collection_state ADD COLUMN received_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_asset_collection_state ADD COLUMN succeeded_sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_asset_collection_state ADD COLUMN succeeded_collected_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_asset_collection_state ADD COLUMN succeeded_received_at BIGINT NOT NULL DEFAULT 0;
