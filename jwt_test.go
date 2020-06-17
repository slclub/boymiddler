package boymiddler

import (
	"github.com/slclub/gnet"
	"github.com/slclub/grouter"
	"github.com/slclub/link"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	//"time"
)

func TestJWTPassNew(t *testing.T) {
	jp := NewJWTPass()
	jp.SetSecret("foo")
	jp.SetIssuer("boy")
	token, err := jp.GenerateToken("usr1", "passwd1")
	assert.Nil(t, err)
	assert.True(t, len(token) > 0)

	claims, err := jp.ParseToken(token)
	assert.Nil(t, err)
	assert.Equal(t, "usr1", claims.Username)

	_, err = jp.ParseToken("")
	assert.NotNil(t, err)
}

func TestJWTPassAuth(t *testing.T) {

	jp := NewJWTPass()
	jp.SetSecret("foo")

	engine := grouter.NewEngine()
	grouter.Group.Use(jp.MiddlerAuth())
	engine.GetRouter().GET("/login/:username/:password", jp.AuthHandle())
	engine.GetRouter().GET("/auth/:token", func(ctx gnet.Contexter) {})

	token := ""
	f1 := func(ctx gnet.Contexter, data map[string]interface{}) {
		v, ok := data["token"]
		if ok {
			token, _ = v.(string)
			assert.True(t, ok)
		}
	}

	jp.SetResponseHandle(f1)
	jp.SetCheckHandle(func(user, pass string) bool { return true })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login/xiaoming/passnow", nil)

	engine.ServeHTTP(w, req)

	link.DEBUG_PRINT("[TOKEN][STRING][AUTH]token:", token)

	req1, _ := http.NewRequest("GET", "/auth?token="+token, nil)
	ctx := gnet.NewContext()
	reqm := gnet.NewRequest()
	resm := &gnet.Response{}
	reqm.InitWithHttp(req1)
	resm.InitSelf(w)
	ctx.SetRequest(reqm)
	ctx.SetResponse(resm)

	//engine.ServeHTTP(w, req)
	jp.MiddlerAuth()(ctx)

	// valid empty token.
	req2, _ := http.NewRequest("GET", "/auth?token="+"", nil)
	ctx.Reset()
	reqm.InitWithHttp(req2)
	assert.Panics(t, func() { jp.MiddlerAuth()(ctx) })

	// valide error token
	req3, _ := http.NewRequest("GET", "/auth?token="+"error token", nil)
	ctx.Reset()
	reqm.InitWithHttp(req3)
	assert.Panics(t, func() { jp.MiddlerAuth()(ctx) })

}

func TestJWTPassErrorAuth(t *testing.T) {
	jp := NewJWTPass()
	engine := grouter.NewEngine()
	grouter.Group.Use(jp.MiddlerAuth())
	engine.GetRouter().GET("/login/:username/:password", jp.AuthHandle())

	// password lenght is too long
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login/xiaoming/passnowdddddddddddddddddd3333333333333333333333333333333333333333333333333333333333333333333333333333333d", nil)
	engine.ServeHTTP(w, req)

	// passwd is empty.
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/login/xiaoming/", nil)
	engine.ServeHTTP(w, req)

}
