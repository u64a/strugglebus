CREATE INDEX idx_messages_reply_to_seq
    ON messages (reply_to, seq);
