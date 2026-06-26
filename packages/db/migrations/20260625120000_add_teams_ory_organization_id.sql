-- +goose Up
-- +goose StatementBegin
ALTER TABLE teams
    ADD COLUMN ory_organization_id UUID;

-- Non-unique: a single Ory organization can map to multiple teams.
CREATE INDEX teams_ory_organization_id_idx
    ON teams (ory_organization_id)
    WHERE ory_organization_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX teams_ory_organization_id_idx;

ALTER TABLE teams
    DROP COLUMN ory_organization_id;
-- +goose StatementEnd
