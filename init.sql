-- 1. Repositories
CREATE TABLE IF NOT EXISTS repositories (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    last_scanned TIMESTAMP
);

-- 2. Files
CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    repo_id INT REFERENCES repositories(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    language TEXT,
    last_modified TIMESTAMP,
    size INT,
    hash TEXT,
    ignored BOOLEAN DEFAULT FALSE
);

-- 3. Code Entities (functions / classes / methods)
CREATE TABLE IF NOT EXISTS code_entities (
    id SERIAL PRIMARY KEY,
    file_id INT REFERENCES files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- function, class, method
    start_line INT,
    end_line INT,
    doc_exists BOOLEAN DEFAULT FALSE,
    doc_last_generated TIMESTAMP,
    last_modified TIMESTAMP,
    hash TEXT,
    visibility TEXT, -- public / private / protected
    decorators TEXT[]
);

-- 4. Doc History (incremental documentation)
CREATE TABLE IF NOT EXISTS doc_history (
    id SERIAL PRIMARY KEY,
    code_entity_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    doc_content TEXT,
    generated_at TIMESTAMP DEFAULT NOW(),
    model TEXT, -- LLM used
    task_type TEXT,
    version_number INT DEFAULT 1
);

-- 5. Chunks (tokenized pieces for LLM context)
CREATE TABLE IF NOT EXISTS chunks (
    id SERIAL PRIMARY KEY,
    code_entity_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    content TEXT,
    type TEXT, -- function_chunk / class_chunk / file_summary
    token_count INT,
    dependencies JSONB,
    order_index INT
);

-- 6. Vector Embeddings (optional for RAG)
CREATE TABLE IF NOT EXISTS vector_embeddings (
    id SERIAL PRIMARY KEY,
    chunk_id INT REFERENCES chunks(id) ON DELETE CASCADE,
    model TEXT,
    embedding BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 7. Call Graph (cross-file / cross-entity dependencies)
CREATE TABLE IF NOT EXISTS call_graph (
    id SERIAL PRIMARY KEY,
    caller_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    callee_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    type TEXT, -- call / import / inheritance
    file_scope TEXT
);

-- 8. Comments Metadata (optional, for token prioritization)
CREATE TABLE IF NOT EXISTS comments_metadata (
    id SERIAL PRIMARY KEY,
    code_entity_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    content TEXT,
    type TEXT, -- inline / block / docstring
    importance INT DEFAULT 1
);

-- =========================
-- CODE REVIEW EXTENSIONS
-- =========================

-- 9. Code Review Sessions
CREATE TABLE IF NOT EXISTS code_review_sessions (
    id SERIAL PRIMARY KEY,
    repo_id INT REFERENCES repositories(id) ON DELETE CASCADE,
    trigger_type TEXT, -- "commit", "manual", "scheduled"
    trigger_ref TEXT,  -- commit hash or branch
    reviewer TEXT,     -- LLM model or human
    created_at TIMESTAMP DEFAULT NOW()
);

-- 10. Code Review Comments
CREATE TABLE IF NOT EXISTS code_review_comments (
    id SERIAL PRIMARY KEY,
    session_id INT REFERENCES code_review_sessions(id) ON DELETE CASCADE,
    code_entity_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    line_start INT,
    line_end INT,
    comment TEXT,
    severity TEXT, -- info / warning / critical
    type TEXT,     -- bug / style / performance / doc
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 11. Code Review Scores
CREATE TABLE IF NOT EXISTS code_review_scores (
    id SERIAL PRIMARY KEY,
    session_id INT REFERENCES code_review_sessions(id) ON DELETE CASCADE,
    code_entity_id INT REFERENCES code_entities(id) ON DELETE CASCADE,
    score INT,        -- e.g., 1-10
    category TEXT,    -- maintainability / readability / performance
    created_at TIMESTAMP DEFAULT NOW()
);
