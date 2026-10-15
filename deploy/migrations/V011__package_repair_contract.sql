-- Old Agents have not declared the installation verification contract.
ALTER TABLE t_agent ADD COLUMN package_repair_contract INTEGER NOT NULL DEFAULT 0;
