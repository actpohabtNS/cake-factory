package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAdmin_JWT(t *testing.T) {
	doRequest := createRequester(t)
	t.Run("getting supadmin jwt", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))
		assertStatus(t, 200, resp)
	})

	t.Run("deny regular user access admin api", func(t *testing.T) {
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

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "whatever",
			"reason": "whatever",
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)
		assertStatus(t, 401, resp)
		assertBody(t, "permission denied", resp)
	})

	t.Run("banning user", func(t *testing.T) {
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

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "bad boy",
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "user test@mail.com banned", resp)

		// banned user JWT generation
		bannedJwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		bannedJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, bannedJwtParams)))

		assertStatus(t, 401, bannedJwtResp)
		assertBody(t, "you are banned! Reason: bad boy", bannedJwtResp)
	})

	t.Run("banning user with wrong email", func(t *testing.T) {
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

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "notAnEmail",
			"reason": "bad boy",
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "must provide an email", resp)
	})

	t.Run("banning not existing user", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "notExist@mail.com",
			"reason": "bad boy",
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "invalid login credentials", resp)
	})

	t.Run("banned user accessing api with jwt", func(t *testing.T) {
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

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// user JWT generation before ban
		userJwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		userJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, userJwtParams)))

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "bad boy",
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "user test@mail.com banned", resp)

		// banned user accessing api
		bannedReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/user/me", nil)
		bannedReq.Header.Set("Authorization", "Bearer "+string(userJwtResp.body))
		bannedResp := doRequest(bannedReq, nil)
		assertStatus(t, 401, bannedResp)
		assertBody(t, "you are banned! Reason: bad boy", bannedResp)
	})

	t.Run("unbanning user", func(t *testing.T) {
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

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "bad boy",
		}
		banReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		banReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		doRequest(banReq, nil)

		// trying unban user
		unbanParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		unbanReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/unban", prepareParams(t, unbanParams))
		unbanReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		doRequest(unbanReq, nil)

		// unbanned user JWT generation
		unbannedJwtParams := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		unbannedJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, unbannedJwtParams)))

		assertStatus(t, 200, unbannedJwtResp)
	})

	t.Run("inspecting user with ban history", func(t *testing.T) {
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

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// trying ban user
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "bad boy",
		}
		banReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		banReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		banTime := time.Now().Format(banTimeFormat)
		doRequest(banReq, nil)
		banStr := "-- was banned (reason: bad boy) at " + banTime + " by " +
			os.Getenv("CAKE_SUPERADMIN_EMAIL") + "\n"

		// trying unban user
		unbanParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		unbanReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/unban", prepareParams(t, unbanParams))
		unbanReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		unbanTime := time.Now().Format(banTimeFormat)
		doRequest(unbanReq, nil)
		unbanStr := "-- was unbanned at " + unbanTime + " by " +
			os.Getenv("CAKE_SUPERADMIN_EMAIL") + "\n"

		// inspecting user
		inspectReq, _ := http.NewRequest(http.MethodGet,
			ts.URL+"/admin/inspect?email=test@mail.com",
			prepareParams(t, jwtParams))
		inspectReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		inspectRest := doRequest(inspectReq, nil)

		assertStatus(t, 200, inspectRest)
		assertBody(t, "user test@mail.com:\n"+banStr+unbanStr, inspectRest)
	})

	t.Run("promoting user", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// future admin registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// regular user registration
		registerRegParams := map[string]interface{}{
			"email":         "simpleUser@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerRegParams)))

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// promoting user
		promoteParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		promoteReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/promote", prepareParams(t, promoteParams))
		promoteReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		promoteResp := doRequest(promoteReq, nil)

		assertStatus(t, 200, promoteResp)
		assertBody(t, "user test@mail.com promoted to admin", promoteResp)

		// promoted user getting JWT
		promotedJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, registerParams)))

		// new admin banning simple user
		banParams := map[string]interface{}{
			"email":  "simpleUser@mail.com",
			"reason": "astronaut",
		}

		banReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		banReq.Header.Set("Authorization", "Bearer "+string(promotedJwtResp.body))
		banResp := doRequest(banReq, nil)

		assertStatus(t, 200, banResp)
		assertBody(t, "user simpleUser@mail.com banned", banResp)
	})

	t.Run("admin accessing superadmin api", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// future admin registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// regular user registration
		registerRegParams := map[string]interface{}{
			"email":         "simpleUser@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerRegParams)))

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// promoting user
		promoteParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		promoteReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/promote", prepareParams(t, promoteParams))
		promoteReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		promoteResp := doRequest(promoteReq, nil)

		assertStatus(t, 200, promoteResp)
		assertBody(t, "user test@mail.com promoted to admin", promoteResp)

		// promoted user getting JWT
		promotedJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, registerParams)))

		// new admin trying to promote simple user
		promoteSimpleParams := map[string]interface{}{
			"email": "simpleUser@mail.com",
		}

		promoteSimpleReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/promote", prepareParams(t, promoteSimpleParams))
		promoteSimpleReq.Header.Set("Authorization", "Bearer "+string(promotedJwtResp.body))
		promoteSimpleResp := doRequest(promoteSimpleReq, nil)

		assertStatus(t, 401, promoteSimpleResp)
		assertBody(t, "permission denied", promoteSimpleResp)
	})

	t.Run("firing admin", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(newRouter(u, jwtService))
		defer ts.Close()

		// future admin registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		// regular user registration
		registerRegParams := map[string]interface{}{
			"email":         "simpleUser@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerRegParams)))

		// superadmin JWT generation
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		jwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, jwtParams)))

		// promoting user
		promoteParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		promoteReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/promote", prepareParams(t, promoteParams))
		promoteReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		promoteResp := doRequest(promoteReq, nil)

		assertStatus(t, 200, promoteResp)
		assertBody(t, "user test@mail.com promoted to admin", promoteResp)

		// firing admin
		fireReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/fire", prepareParams(t, promoteParams))
		fireReq.Header.Set("Authorization", "Bearer "+string(jwtResp.body))
		fireResp := doRequest(fireReq, nil)

		assertStatus(t, 200, fireResp)
		assertBody(t, "admin test@mail.com downgraded to user", fireResp)

		// fired user getting JWT
		promotedJwtResp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, registerParams)))

		// fired admin banning simple user
		banParams := map[string]interface{}{
			"email":  "simpleUser@mail.com",
			"reason": "astronaut",
		}

		banReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/ban", prepareParams(t, banParams))
		banReq.Header.Set("Authorization", "Bearer "+string(promotedJwtResp.body))
		banResp := doRequest(banReq, nil)

		assertStatus(t, 401, banResp)
		assertBody(t, "permission denied", banResp)
	})
}
