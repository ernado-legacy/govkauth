package govkauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
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
	fieldsParameter       = "fields"
	fiealdsValue          = "photo_max,sex,bdate,photo"
	authAction            = "authorize"
	codeParameter         = "code"
	usersGetAction        = "users.get"
	uidsParameter         = "uids"
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
		ID        int64  `json:"id"`
		Photo     string `json:"photo_max"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Sex       int    `json:"sex"`
		Birthday  string `json:"bdate"`
	}
}

type User struct {
	ID       int64 `json:"uid"`
	Photo    string
	Name     string `json:"name"`
	Sex      string `json:"gender"`
	Email    string `json:"email"`
	Birthday time.Time
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

func (client *Client) GetName(uid int64) (user User, err error) {
	link := client.base(fmt.Sprintf("method/%s", usersGetAction))
	link.Host = "api.vk.com"
	q := link.Query()
	q.Del(appIDParameter)
	q.Del(redirectParameter)
	q.Add(uidsParameter, fmt.Sprint(uid))
	link.RawQuery = q.Encode()
	res, err := httpClient.Get(link.String())
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
	u := answer.Response[0]
	user.Name = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
	user.ID = u.ID
	user.Photo = u.Photo
	user.Birthday, _ = time.Parse("01.02.2006", u.Birthday)
	if u.Sex == 2 {
		user.Sex = "male"
	}
	if u.Sex == 1 {
		user.Sex = "female"
	}
	return user, err
}
