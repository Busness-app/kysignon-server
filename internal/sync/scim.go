package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
)

func supportedSystemType(kind string) bool {
	switch kind {
	case "scim", "suite_webhook", "kypost", "kypasswords", "kybookmarks", "kynotes":
		return true
	}
	return false
}

func validateSCIMConfig(raw, token string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return scim.ErrInsecureURL
	}
	if len(token) == 0 || len(token) > 8192 || strings.IndexFunc(token, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return errors.New("bearer token must contain 1–8192 visible ASCII characters without spaces")
	}
	return nil
}

func (e *Engine) scimClient(sys *store.PairedSystem, secret string) *scim.Client {
	// Migrate the old UI's /Users endpoint form without changing the stored target.
	return &scim.Client{BaseURL: strings.TrimSuffix(strings.TrimRight(sys.CallbackURL, "/"), "/Users"), Token: secret, HTTPClient: e.httpClient}
}

// Never store remote text, URLs, or wrapped transport errors: a server can echo
// credentials in a Location or error body, including transformed credentials.
func deliveryError(err error) string {
	var remote *scim.Error
	if errors.As(err, &remote) {
		return fmt.Sprintf("SCIM HTTP %d", remote.Status)
	}
	for _, kind := range []error{scim.ErrAmbiguous, scim.ErrMalformedResponse, scim.ErrUnauthorized, scim.ErrInsecureURL, scim.ErrNotFound, errCreateUncertain} {
		if errors.Is(err, kind) {
			return kind.Error()
		}
	}
	return "delivery failed; check connector configuration and downstream availability"
}

var errCreateUncertain = errors.New("SCIM create outcome unresolved; reconcile externalId at the target before retrying")

// The released primitive's FindUser treats an empty page as not-found regardless
// of totalResults. Own the bounded collection read until the library supports
// strict pagination; all resource writes still use the shared client.
func (e *Engine) findSCIMUser(ctx context.Context, c *scim.Client, localID string) (scim.User, error) {
	if err := validateSCIMConfig(c.BaseURL, c.Token); err != nil {
		return scim.User{}, err
	}
	u, _ := url.Parse(c.BaseURL)
	u = u.JoinPath("Users")
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(localID)
	u.RawQuery = url.Values{"filter": {`externalId eq "` + quoted + `"`}, "startIndex": {"1"}, "count": {"2"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return scim.User{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/scim+json")
	client := *e.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }
	resp, err := client.Do(req)
	if err != nil {
		return scim.User{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return scim.User{}, scim.ErrMalformedResponse
	}
	if resp.StatusCode == http.StatusNotFound {
		return scim.User{}, scim.ErrMalformedResponse
	}
	if resp.StatusCode != http.StatusOK {
		d := time.Duration(0)
		h := resp.Header.Get("Retry-After")
		if seconds, err := strconv.ParseInt(h, 10, 64); err == nil {
			d = time.Duration(max(0, min(seconds, 3600))) * time.Second
		} else if t, err := http.ParseTime(h); err == nil {
			d = max(0, min(time.Until(t), time.Hour))
		}
		return scim.User{}, &scim.Error{Status: resp.StatusCode, RetryAfter: d}
	}
	var page struct {
		Total     *int        `json:"totalResults"`
		Start     *int        `json:"startIndex"`
		Resources []scim.User `json:"Resources"`
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &page) != nil || page.Total == nil || *page.Total < 0 || (page.Start != nil && *page.Start != 1) {
		return scim.User{}, scim.ErrMalformedResponse
	}
	if *page.Total > 1 || len(page.Resources) > 1 {
		return scim.User{}, scim.ErrAmbiguous
	}
	// A unique filtered result fits on the first page. Partial/contradictory pages
	// must fail closed rather than create a duplicate or select an unrelated user.
	if *page.Total != len(page.Resources) {
		return scim.User{}, scim.ErrMalformedResponse
	}
	if *page.Total == 0 {
		return scim.User{}, scim.ErrNotFound
	}
	found := page.Resources[0]
	if found.ID == "" || found.ID == "." || found.ID == ".." || found.ExternalID != localID {
		return scim.User{}, scim.ErrMalformedResponse
	}
	return found, nil
}

func (e *Engine) deliverSCIM(ctx context.Context, sys *store.PairedSystem, secret, eventType, localID string, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if localID == "" {
		return errors.New("missing local user ID")
	}
	switch eventType {
	case "user.created", "user.updated", "user.deleted", "user.mfa_reset":
	default:
		return errors.New("unsupported user event")
	}
	// MFA credentials are never provisioned through generic SCIM.
	if eventType == "user.mfa_reset" {
		return nil
	}
	c := e.scimClient(sys, secret)
	if err := validateSCIMConfig(c.BaseURL, secret); err != nil {
		return err
	}
	remoteID, started, err := e.store.SCIMUserLink(sys.ID, localID)
	if err != nil {
		return err
	}
	var desired scim.User
	if eventType != "user.deleted" {
		if err = json.Unmarshal(payload, &desired); err != nil || desired.UserName == "" {
			return scim.ErrMalformedResponse
		}
		desired.ID = ""
		desired.Meta = nil
		desired.ExternalID = localID
	}
	if remoteID == "" {
		found, lookupErr := e.findSCIMUser(ctx, c, localID)
		if lookupErr == nil {
			remoteID = found.ID
			if err = e.store.SaveSCIMUserLink(sys.ID, localID, remoteID); err != nil {
				return err
			}
		} else if !errors.Is(lookupErr, scim.ErrNotFound) {
			return lookupErr
		} else {
			if started {
				return errCreateUncertain
			}
			if eventType == "user.deleted" {
				return nil
			}
			won, err := e.store.StartSCIMCreate(sys.ID, localID)
			if err != nil {
				return err
			}
			if !won {
				return errCreateUncertain
			}
			created, err := c.CreateUser(ctx, desired)
			if err != nil {
				var rejection *scim.Error
				if errors.As(err, &rejection) && rejection.Status >= 400 && rejection.Status < 500 && rejection.Status != http.StatusRequestTimeout {
					if clearErr := e.store.RejectSCIMCreate(sys.ID, localID); clearErr != nil {
						return clearErr
					}
				}
				// Conflict may be our create whose response was lost, but an unrelated
				// conflict is never success. Other uncertain failures reconcile next retry.
				if !errors.Is(err, scim.ErrConflict) {
					return err
				}
				found, lookupErr := e.findSCIMUser(ctx, c, localID)
				if lookupErr != nil {
					return err
				}
				remoteID = found.ID
			} else {
				if created.ExternalID != "" && created.ExternalID != localID {
					return scim.ErrMalformedResponse
				}
				return e.store.SaveSCIMUserLink(sys.ID, localID, created.ID)
			}
			if err = e.store.SaveSCIMUserLink(sys.ID, localID, remoteID); err != nil {
				return err
			}
		}
	}
	if eventType == "user.deleted" {
		// Deactivate rather than erase the downstream user's data.
		current, err := c.GetUser(ctx, remoteID)
		if errors.Is(err, scim.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != remoteID || current.ExternalID != localID {
			return scim.ErrMalformedResponse
		}
		_, err = c.PatchUser(ctx, remoteID, scim.PatchOperation{Op: "replace", Path: "active", Value: false})
		if errors.Is(err, scim.ErrNotFound) {
			return nil
		}
		return err
	}
	_, err = c.ReplaceUser(ctx, remoteID, desired)
	return err
}

func (e *Engine) TestSystem(ctx context.Context, sys *store.PairedSystem) error {
	if sys.SystemType != "scim" {
		return errors.New("connection testing is available for generic SCIM connectors")
	}
	secret, err := e.SigningSecret(sys)
	if err != nil {
		return err
	}
	// A filtered Users read checks authenticated directory access; discovery may
	// be public. An empty result is a valid authenticated collection response.
	_, err = e.findSCIMUser(ctx, e.scimClient(sys, secret), "kysignon-connection-test")
	if errors.Is(err, scim.ErrNotFound) {
		return nil
	}
	return err
}

// ReviewSystem permits an explicit choice for legacy custom connectors, or token
// replacement for SCIM. Established suite protocols cannot be switched accidentally.
func (e *Engine) ReviewSystem(sys *store.PairedSystem, kind, token string, audit *store.AuditEvent) error {
	if kind != "scim" && kind != "suite_webhook" {
		return errors.New("choose scim or suite_webhook")
	}
	if supportedSystemType(sys.SystemType) && sys.SystemType != kind {
		return errors.New("an established connector cannot change protocol")
	}
	encrypted := sys.HMACSecretEncrypted
	if kind == "scim" {
		if err := validateSCIMConfig(sys.CallbackURL, token); err != nil {
			return err
		}
		var err error
		encrypted, err = crypto.EncryptAESGCM(e.encryptionKey, []byte(token))
		if err != nil {
			return err
		}
	} else if token != "" {
		return errors.New("suite webhook retains its existing signing secret")
	}
	return e.store.ConfigureSystem(sys.ID, sys.SystemType, kind, encrypted, audit)
}
