CREATE TABLE t_clamav_status (
    agent_id VARCHAR(64) PRIMARY KEY REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    contract INTEGER NOT NULL DEFAULT 0,
    coverage TEXT NOT NULL DEFAULT '{}',
    observed_at BIGINT NOT NULL
);
ALTER TABLE t_virus_scan_task ADD COLUMN scan_engine VARCHAR(16) NOT NULL DEFAULT 'builtin';
ALTER TABLE t_virus_task_agent ADD COLUMN expected_engine_version VARCHAR(256) NOT NULL DEFAULT '';
UPDATE t_virus_task_agent SET expected_engine_version=COALESCE((SELECT t.expected_db_version FROM t_virus_scan_task t WHERE t.id=t_virus_task_agent.task_id),'');
