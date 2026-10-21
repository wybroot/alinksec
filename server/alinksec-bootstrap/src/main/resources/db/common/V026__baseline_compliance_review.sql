-- Append-only evidence decisions, bound to an immutable task/package snapshot.
CREATE TABLE t_baseline_compliance_review (
    task_id BIGINT NOT NULL REFERENCES t_baseline_task(id),
    agent_id TEXT NOT NULL,
    template_id BIGINT NOT NULL,
    control_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    decision TEXT NOT NULL CHECK (decision IN ('pass','fail','not_applicable','pending')),
    note TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    reviewed_by BIGINT NOT NULL,
    reviewed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (task_id,agent_id,template_id,control_id,revision)
);
