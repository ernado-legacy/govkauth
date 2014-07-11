package govkauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

const (
	host                  = "oauth.vk.com"
	scheme                = "https"
	accessTokenAction     = "access_token"
	appIDParameter        = "client_id"
	appSecretParameter    = "client_secret"
	version               = "5.23"
	versionParameter      = "v"
	responseTypeParameter = "response_type"
	responseTypeCode      = "code"
	redirectParameter     = "redirect_uri"
	scopeParameter        = "scope"
	authAction            = "authorize"
	codeParameter         = "code"
	usersGetAction        = "users.get"
)

var (
	// ErrorBadCode occures when server returns blank code or error
	ErrorBadCode = errors.New("bad code")
	// ErrorBadResponse occures when server returns unexpected response
	ErrorBadResponse                = errors.New("bad server response")
	httpClient       mockHTTPClient = &http.Client{}
)

// Client for vkontakte oauth
type Client struct {
	ID          string
	Secret      string
	RedirectURL string
	Scope       string
}

type usersAnswer struct {
	Response []struct {
		ID        string `json:"uid"`
		Photo     string `json:"photo"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
}

// AccessToken describes oath server response
type AccessToken struct {
	AccessToken string `json:"access_token"`
	Email       string `json:"email"`
	Expires     int    `json:"expires_in"`
	UserID      int64  `json:"user_id"`
}

type mockHTTPClient interface {
	Get(url string) (res *http.Response, err error)
}

func (client *Client) base(action string) url.URL {
	u := url.URL{}
	u.Host = host
	u.Scheme = scheme
	u.Path = action

	query := u.Query()
	query.Add(appIDParameter, client.ID)
	query.Add(redirectParameter, client.RedirectURL)

	u.RawQuery = query.Encode()
	return u
}

// DialogURL is url for vk auth dialog
func (client *Client) DialogURL() url.URL {
	u := client.base(authAction)

	query := u.Query()
	query.Add(scopeParameter, client.Scope)
	query.Add(responseTypeParameter, responseTypeCode)
	query.Add(versionParameter, version)

	u.RawQuery = query.Encode()
	return u
}

func (client *Client) accessTokenURL(code string) url.URL {
	u := client.base(accessTokenAction)

	query := u.Query()
	query.Add(appSecretParameter, client.Secret)
	query.Add(codeParameter, code)

	u.RawQuery = query.Encode()
	return u
}

// GetAccessToken is handler for redirect, gets and returns access token
func (client *Client) GetAccessToken(req *http.Request) (token *AccessToken, err error) {
	query := req.URL.Query()
	code := query.Get(codeParameter)
	if code == "" {
		err = ErrorBadCode
		return nil, err
	}

	requestURL := client.accessTokenURL(code)
	res, err := httpClient.Get(requestURL.String())
	if err != nil {
		return nil, err
	}

	token = &AccessToken{}
	decoder := json.NewDecoder(res.Body)
	return token, decoder.Decode(token)
}

func (client *Client) GetName(uid int64) (name string, err error) {
	u := client.base(usersGetAction)
	q := u.Query()
	q.Del(appIDParameter)
	q.Del(redirectParameter)
	u.RawQuery = q.Encode()
	res, err := httpClient.Get(u.String())
	if err != nil {
		return
	}
	answer := &usersAnswer{}
	decoder := json.NewDecoder(res.Body)
	if err = decoder.Decode(answer); err != nil {
		return
	}
	if len(answer.Response) != 1 {
		err = ErrorBadResponse
		return
	}
	user := answer.Response[0]
	return fmt.Sprintf("%s %s", user.FirstName, user.LastName), nil
}
