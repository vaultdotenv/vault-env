-- Store permission + env_scope on invites so they're applied on accept
ALTER TABLE invites ADD COLUMN permission TEXT NOT NULL DEFAULT 'write';
ALTER TABLE invites ADD COLUMN env_scope TEXT DEFAULT NULL;
