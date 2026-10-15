-- Historical inventories remain of unknown completeness. Never infer package
-- architecture or distribution identity from the Agent's architecture/OS label.
ALTER TABLE t_asset_software ADD COLUMN architecture VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE t_agent ADD COLUMN distro_id VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE t_agent ADD COLUMN distro_version VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE t_agent ADD COLUMN software_inventory_source VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE t_agent ADD COLUMN software_identity_error VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE t_agent ADD COLUMN software_collection_status VARCHAR(32) NOT NULL DEFAULT 'legacy';
ALTER TABLE t_agent ADD COLUMN software_collection_error VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE t_agent ADD COLUMN software_attempted_at TIMESTAMP;
ALTER TABLE t_agent ADD COLUMN software_succeeded_at TIMESTAMP;
