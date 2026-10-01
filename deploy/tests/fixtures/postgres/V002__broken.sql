CREATE TABLE t_migration_rollback_probe (id INTEGER PRIMARY KEY);
UPDATE t_agent SET hostname = 'changed-by-broken-migration'
WHERE agent_id = 'migration-fixture-agent';
SELECT migration_test_missing_function();
