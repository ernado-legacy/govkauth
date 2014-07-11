package govkauth

import (
	"bytes"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"net/http"
	"testing"
)

type MockClient struct {
	Response *http.Response
}

func (c *MockClient) Get(url string) (res *http.Response, err error) {
	err = nil
	if c.Response == nil {
		err = http.ErrShortBody
	}
	return c.Response, err
}

func TestClient(t *testing.T) {
	client := Client{"APP_ID", "APP_SECRET", "REDIRECT_URI", "PERMISSIONS"}
	Convey("TestUrl", t, func() {
		url := client.DialogURL()
		should := "https://oauth.vk.com/authorize?client_id=APP_ID&redirect_uri=REDIRECT_URI&response_type=code&scope=PERMISSIONS&v=5.23"
		So(url.String(), ShouldEqual, should)
	})

	Convey("Test getName", t, func() {
		res := &http.Response{}
		body := `{"response":[{"uid":1,"first_name":"Павел","last_name":"Дуров","photo":"http://cs109.vkontakte.ru/u00001/c_df2abf56.jpg"}]}`
		res.Body = ioutil.NopCloser(bytes.NewBufferString(body))
		httpClient = &MockClient{res}
		name, err := client.GetName(1)
		So(err, ShouldBeNil)
		So(name, ShouldEqual, "Павел Дуров")

		Convey("Multiple response", func() {
			body := `{"response":[{"uid":1,"first_name":"Павел","last_name":"Дуров","photo":"http://cs109.vkontakte.ru/u00001/c_df2abf56.jpg"}, {"uid":2,"first_name":"Павел","last_name":"Дуров","photo":"http://cs109.vkontakte.ru/u00001/c_df2abf56.jpg"}]}`
			res.Body = ioutil.NopCloser(bytes.NewBufferString(body))
			_, err := client.GetName(1)
			So(err, ShouldEqual, ErrorBadResponse)
		})

		Convey("Http error", func() {
			httpClient = &MockClient{nil}
			_, err := client.GetName(1)
			So(err, ShouldNotBeNil)
		})

		Convey("Server error", func() {
			body := `{"response": {"error": "500"}}`
			res.Body = ioutil.NopCloser(bytes.NewBufferString(body))
			_, err := client.GetName(1)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Test accessTokenUrl", t, func() {
		Convey("Request url ok", func() {
			urlStr := "https://oauth.vk.com/access_token?client_id=APP_ID&client_secret=APP_SECRET&code=CODE&redirect_uri=REDIRECT_URI"
			url := client.accessTokenURL("CODE")
			So(url.String(), ShouldEqual, urlStr)
		})

		urlStr := "http://REDIRECT_URI?code=7a6fa4dff77a228eeda56603b8f53806c883f011c40b72630bb50df056f6479e52a"
		req, _ := http.NewRequest("GET", urlStr, nil)

		resTok := &http.Response{}
		body := `{"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3", "expires_in":43200, "user_id":6492}`
		resTok.Body = ioutil.NopCloser(bytes.NewBufferString(body))
		httpClient = &MockClient{resTok}

		tok, err := client.GetAccessToken(req)
		So(err, ShouldBeNil)
		So(tok.AccessToken, ShouldEqual, "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3")
		So(tok.Expires, ShouldEqual, 43200)
		So(tok.UserID, ShouldEqual, int64(6492))

		Convey("Bad response", func() {
			resTok.Body = ioutil.NopCloser(bytes.NewBufferString("asdfasdf"))
			httpClient = &MockClient{resTok}
			_, err := client.GetAccessToken(req)
			So(err, ShouldNotBeNil)
		})

		Convey("Bad urk", func() {
			req, _ = http.NewRequest("GET", "http://REDIRECT_URI?error=kek", nil)
			_, err := client.GetAccessToken(req)
			So(err, ShouldNotBeNil)
		})

		Convey("Http error", func() {
			httpClient = &MockClient{nil}
			_, err := client.GetAccessToken(req)
			So(err, ShouldNotBeNil)
		})
	})
}
