package devops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type AzureTokenSource struct {
	DevopsConfig oauth2.Config
	State        string
	AuthHandler  authhandler.AuthorizationHandler
}

func (source AzureTokenSource) Token() (*oauth2.Token, error) {
	authCodeUrl := getAuthorizationRequestAzure(&source.DevopsConfig, source.State)
	code, state, err := source.AuthHandler(authCodeUrl)
	if err != nil {
		return nil, err
	}
	if state != source.State {
		return nil, errors.New("state mismatch in 3-legged-OAuth flow")
	}
	token, err := requestTokenAzure(&source.DevopsConfig, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func requestTokenAzure(c *oauth2.Config, code string) (*oauth2.Token, error) {
	body := fmt.Sprintf("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=%s&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s&redirect_uri=%s",
		url.QueryEscape(c.ClientSecret),
		url.QueryEscape(code),
		c.RedirectURL,
	)
	req, err := http.NewRequest(http.MethodPost, c.Endpoint.TokenURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fmt.Fprintln(os.Stderr, "request url:", req.URL)
	fmt.Fprintln(os.Stderr, "req body:", body)
	hc := http.Client{}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tokenResponse:", string(bodyBytes))
	var tokenBody tokenResponse
	err = json.Unmarshal(bodyBytes, &tokenBody)
	if err != nil {
		return nil, err
	}
	timeInSeconds, err := strconv.Atoi(tokenBody.ExpiresIn)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken:  tokenBody.AccessToken,
		TokenType:    tokenBody.TokenType,
		RefreshToken: tokenBody.RefreshToken,
		Expiry:       time.Unix(int64(timeInSeconds), 0),
	}, nil
}

func getAuthorizationRequestAzure(config *oauth2.Config, state string) string {
	var buf bytes.Buffer
	buf.WriteString(config.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"Assertion"},
		"client_id":     {config.ClientID},
	}
	if config.RedirectURL != "" {
		v.Set("redirect_uri", config.RedirectURL)
	}
	if len(config.Scopes) > 0 {
		v.Set("scope", strings.Join(config.Scopes, " "))
	}
	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}
	if strings.Contains(config.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
