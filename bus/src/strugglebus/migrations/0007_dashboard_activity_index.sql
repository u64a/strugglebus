CREATE INDEX idx_messages_channel_agent_seq
    ON messages (channel_id, agent_id, seq);
