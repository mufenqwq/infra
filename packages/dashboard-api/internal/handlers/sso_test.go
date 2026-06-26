package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/e2b-dev/infra/packages/auth/pkg/auth"
	authtypes "github.com/e2b-dev/infra/packages/auth/pkg/types"
	"github.com/e2b-dev/infra/packages/dashboard-api/internal/cfg"
	internalteamprovision "github.com/e2b-dev/infra/packages/dashboard-api/internal/teamprovision"
	authqueries "github.com/e2b-dev/infra/packages/db/pkg/auth/queries"
	"github.com/e2b-dev/infra/packages/db/pkg/testutils"
)

// ssoUserProfiles is a Provider whose SSO-organization lookups are configurable,
// so tests can simulate identities that belong to an Ory organization.
type ssoUserProfiles struct {
	handlerTestUserProfiles

	orgBySubject map[string]string
	orgByUser    map[uuid.UUID]string
}

func (p ssoUserProfiles) GetIdentitySSOOrganization(_ context.Context, subject string) (string, error) {
	return p.orgBySubject[subject], nil
}

func (p ssoUserProfiles) GetUserSSOOrganization(_ context.Context, userID uuid.UUID) (string, error) {
	return p.orgByUser[userID], nil
}

func setTeamSSOOrg(t *testing.T, db *testutils.Database, teamID, orgID uuid.UUID, createdAt time.Time) {
	t.Helper()

	if err := db.SqlcClient.TestsRawSQL(t.Context(),
		"UPDATE public.teams SET ory_organization_id = $1, created_at = $2 WHERE id = $3",
		orgID, createdAt, teamID,
	); err != nil {
		t.Fatalf("failed to set team sso org: %v", err)
	}
}

func TestBootstrapOIDCUser_SSOJoinsMappedTeams(t *testing.T) {
	t.Parallel()

	testDB := testutils.SetupDatabase(t)
	ctx := t.Context()
	sink := &fakeTeamProvisionSink{}

	orgID := uuid.New()
	subject := uuid.NewString()

	// teamOlder is given an earlier created_at, so it must become the default.
	teamNewer := testutils.CreateTestTeam(t, testDB)
	teamOlder := testutils.CreateTestTeam(t, testDB)
	setTeamSSOOrg(t, testDB, teamNewer, orgID, time.Now().Add(-1*time.Hour))
	setTeamSSOOrg(t, testDB, teamOlder, orgID, time.Now().Add(-2*time.Hour))

	store := &APIStore{
		config:            cfg.Config{OryIssuerURL: "https://ory.example.test"},
		db:                testDB.SqlcClient,
		authDB:            testDB.AuthDB,
		teamProvisionSink: sink,
		userProfiles:      ssoUserProfiles{orgBySubject: map[string]string{subject: orgID.String()}},
	}

	input := oidcUserBootstrapInput{
		OIDCIssuer:    "https://ory.example.test",
		OIDCUserID:    subject,
		OIDCUserEmail: "ada@example.test",
	}

	team, err := store.bootstrapOIDCUser(ctx, input)
	if err != nil {
		t.Fatalf("expected sso bootstrap to succeed: %v", err)
	}
	if team.ID != teamOlder {
		t.Fatalf("expected default team %s (earliest created), got %s", teamOlder, team.ID)
	}

	userIdentity, err := testDB.AuthDB.Read.GetUserIdentity(ctx, authqueries.GetUserIdentityParams{
		OidcIss: input.OIDCIssuer,
		OidcSub: input.OIDCUserID,
	})
	if err != nil {
		t.Fatalf("expected user identity to be created: %v", err)
	}

	defaultTeam, err := testDB.AuthDB.Read.GetDefaultTeamByUserID(ctx, userIdentity.UserID)
	if err != nil {
		t.Fatalf("expected default team: %v", err)
	}
	if defaultTeam.ID != teamOlder {
		t.Fatalf("expected default team %s, got %s", teamOlder, defaultTeam.ID)
	}

	memberships, err := testDB.AuthDB.Read.GetTeamsWithUsersTeams(ctx, userIdentity.UserID)
	if err != nil {
		t.Fatalf("failed to read memberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("expected membership in both mapped teams, got %d", len(memberships))
	}
	joined := map[uuid.UUID]bool{}
	for _, m := range memberships {
		joined[m.Team.ID] = true
	}
	if !joined[teamOlder] || !joined[teamNewer] {
		t.Fatalf("expected membership in both %s and %s, got %v", teamOlder, teamNewer, joined)
	}

	if len(sink.requests) != 0 {
		t.Fatalf("expected no billing provisioning for SSO teams, got %d", len(sink.requests))
	}
}

func TestBootstrapOIDCUser_SSOFailsClosedWhenNoTeamMapped(t *testing.T) {
	t.Parallel()

	testDB := testutils.SetupDatabase(t)
	ctx := t.Context()
	sink := &fakeTeamProvisionSink{}

	orgID := uuid.New()
	subject := uuid.NewString()

	store := &APIStore{
		config:            cfg.Config{OryIssuerURL: "https://ory.example.test"},
		db:                testDB.SqlcClient,
		authDB:            testDB.AuthDB,
		teamProvisionSink: sink,
		userProfiles:      ssoUserProfiles{orgBySubject: map[string]string{subject: orgID.String()}},
	}

	input := oidcUserBootstrapInput{
		OIDCIssuer:    "https://ory.example.test",
		OIDCUserID:    subject,
		OIDCUserEmail: "grace@example.test",
	}

	_, err := store.bootstrapOIDCUser(ctx, input)
	if err == nil {
		t.Fatal("expected fail-closed error when organization maps to no team")
	}

	var provErr *internalteamprovision.ProvisionError
	if !errors.As(err, &provErr) || provErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 ProvisionError, got %v", err)
	}

	// The transaction must roll back: no identity or personal team is left behind.
	if _, err := testDB.AuthDB.Read.GetUserIdentity(ctx, authqueries.GetUserIdentityParams{
		OidcIss: input.OIDCIssuer,
		OidcSub: input.OIDCUserID,
	}); err == nil {
		t.Fatal("expected no user identity after fail-closed bootstrap")
	}

	if len(sink.requests) != 0 {
		t.Fatalf("expected no billing provisioning, got %d", len(sink.requests))
	}
}

func TestCreateTeam_SSOUserRejected(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	userID := uuid.New()

	store := &APIStore{
		userProfiles: ssoUserProfiles{orgByUser: map[uuid.UUID]string{userID: uuid.NewString()}},
	}

	_, err := store.createTeam(ctx, userID, "My Team")
	if err == nil {
		t.Fatal("expected SSO user to be blocked from creating a team")
	}

	var provErr *internalteamprovision.ProvisionError
	if !errors.As(err, &provErr) || provErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 ProvisionError, got %v", err)
	}
}

func TestPostTeamsTeamIDMembers_SSOManagedTeamRejected(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	teamID := uuid.New()
	orgID := uuid.New()

	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	auth.SetTeamInfoForTest(t, ginCtx, &authtypes.Team{
		Team: &authqueries.Team{ID: teamID, OryOrganizationID: &orgID},
	})
	ginCtx.Request = httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(`{"email":"newbie@example.test"}`))
	ginCtx.Request.Header.Set("Content-Type", "application/json")

	store := &APIStore{}
	store.PostTeamsTeamIDMembers(ginCtx, teamID)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}
