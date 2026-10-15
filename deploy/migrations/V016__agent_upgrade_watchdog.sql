-- Legacy Agents cannot guarantee startup health or automatic rollback.
ALTER TABLE t_agent ADD COLUMN upgrade_contract INTEGER NOT NULL DEFAULT 0;
