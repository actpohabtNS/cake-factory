package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}

		res, httpErr := http.DefaultClient.Do(req)
		if httpErr != nil {
			t.Errorf("unexpected error: %v", httpErr)
			return parsedResponse{}
		}

		resp, ioErr := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		if closeErr != nil {
			return parsedResponse{}
		}
		if ioErr != nil {
			t.Errorf("unexpected error: %v", ioErr)
			return parsedResponse{}
		}

		return parsedResponse{res.StatusCode, resp}
	}
}

func prepareParams(t *testing.T, params map[string]interface{}) io.Reader {
	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	return bytes.NewBuffer(body)
}

func newTestUserService() *UserService {
	return &UserService{
		repository: NewInMemoryUserStorage(),
	}
}

func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d,actual: %d", expected, r.status)
	}
}

func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s,actual: %s", expected, actual)
	}
}

func TestUsers_JWT(t *testing.T) {
	doRequest := createRequester(t)
	t.Run("user does not exist", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(newLoggingRouter(u, j))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login credentials", resp)
	})

	t.Run("registration", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})

	t.Run("adding already registered user", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "user already exists", resp)
	})

	t.Run("wrong password", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "wrongpass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login credentials", resp)
	})

	t.Run("getting cake without jwt", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL+"/user/me", nil))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})

	t.Run("getting user info", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/user/me", nil)
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)
		assertStatus(t, 200, resp)
		assertBody(t, "[test@mail.com], your favourite cake is cheesecake", resp)
	})

	t.Run("changing login must be an email", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// JWT generation
		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// email updating
		updateEmailParams := map[string]interface{}{
			"email":         "notAnEmail",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/user/email", prepareParams(t, updateEmailParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "must provide an email", resp)
	})

	t.Run("short updating password", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// JWT generation
		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// password updating
		updatePasswordParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "short",
			"favorite_cake": "cheesecake",
		}
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/user/password", prepareParams(t, updatePasswordParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "password must be at least 8 symbols", resp)
	})

	t.Run("null cake", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "favourite cake can't be empty", resp)
	})

	t.Run("cake with numbers", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake1",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "favourite cake must contain only alphabetic characters", resp)
	})

	t.Run("wrong request params", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", bytes.NewBuffer([]byte("blah"))))
		assertStatus(t, 422, resp)
		assertBody(t, "could not read params", resp)
	})

	t.Run("updating favorite cake", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// JWT generation
		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// cake updating
		updateCakeParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cinnabon",
		}
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/user/favorite_cake", prepareParams(t, updateCakeParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "favorite cake updated", resp)

		// user info printing
		req, _ = http.NewRequest(http.MethodGet, ts.URL+"/user/me", nil)
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp = doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "[test@mail.com], your favourite cake is cinnabon", resp)
	})

	t.Run("updating email", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// JWT generation
		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// email updating
		updateEmailParams := map[string]interface{}{
			"email":         "another@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/user/email", prepareParams(t, updateEmailParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "email updated", resp)

		// new JWT generation
		newJwtParams := map[string]interface{}{
			"email":    "another@mail.com",
			"password": "somepass",
		}
		newJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, newJwtParams)))

		// user info printing
		req, _ = http.NewRequest(http.MethodGet, ts.URL+"/user/me", nil)
		req.Header.Set("Authorization", "Bearer "+string(newJwtResp.body))
		resp = doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "[another@mail.com], your favourite cake is cheesecake", resp)
	})

	t.Run("updating password", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// JWT generation
		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// password updating
		updatePasswordParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "anotherpass",
			"favorite_cake": "cheesecake",
		}
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/user/password", prepareParams(t, updatePasswordParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "password updated", resp)

		// user info printing
		req, _ = http.NewRequest(http.MethodGet, ts.URL+"/user/me", nil)
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp = doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "[test@mail.com], your favourite cake is cheesecake", resp)
	})

	t.Run("updating password of another user with my jwt", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// JWT generation
		jwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// password updating
		updatePasswordParams := map[string]interface{}{
			"email":         "myEnemy@mail.com",
			"password":      "myPassword",
			"favorite_cake": "cheesecake",
		}
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/user/password", prepareParams(t, updatePasswordParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})
}
