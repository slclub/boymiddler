package boymiddler

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"github.com/slclub/gnet"
	"github.com/slclub/gnet/defined"
	"github.com/slclub/link"
	"time"
)

type Claims struct {
	Username string
	Password string
	jwt.StandardClaims
}

type auth struct {
	Username string `validate:"required;MaxSize(50)`
	Password string `validate:"required;MaxSize(50)`
}

var Validator *validator.Validate = validator.New()

// use secret key.
type JWTPass struct {
	timeout time.Duration
	// publisher.
	issuer string
	secret []byte

	check_handle func(username, password string) bool
	res_handle   func(ctx gnet.Contexter, data map[string]interface{})
}

func NewJWTPass() *JWTPass {
	jp := &JWTPass{}
	jp.Initialize()
	return jp
}

func (jp *JWTPass) Initialize() {
	jp.timeout = 3 * time.Hour
	jp.issuer = "boy"
	jp.check_handle = func(username, password string) bool { return true }
	jp.res_handle = func(ctx gnet.Contexter, data map[string]interface{}) {}
}

//  generate token by paramters.
func (jp *JWTPass) GenerateToken(username, password string) (string, error) {
	now := time.Now()
	expire := now.Add(jp.timeout * time.Hour)

	claims := Claims{
		Username: username,
		Password: password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expire.Unix(),
			Issuer:    jp.issuer,
		},
	}

	token_claims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := token_claims.SignedString(jp.secret)
	return token, err
}

// parse claim with token.
func (jp *JWTPass) ParseToken(token string) (*Claims, error) {
	token_claims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jp.secret, nil
	})

	if token_claims == nil {
		return nil, err
	}
	claims, ok := token_claims.Claims.(*Claims)
	if !ok || !token_claims.Valid {
		return nil, err
	}
	return claims, nil
}

func (jp *JWTPass) SetSecret(secret string) {
	jp.secret = []byte(secret)
}

func (jp *JWTPass) SetIssuer(issuer string) {
	jp.issuer = issuer
}

func (jp *JWTPass) SetCheckHandle(handle func(user, pass string) bool) {
	jp.check_handle = handle
}

func (jp *JWTPass) SetResponseHandle(handle func(ctx gnet.Contexter, data map[string]interface{})) {
	jp.res_handle = handle
}

// default generate token with login handle.
func (jp *JWTPass) AuthHandle() gnet.HandleFunc {
	return func(ctx gnet.Contexter) {
		username, _ := ctx.Request().GetString("username")
		password, _ := ctx.Request().GetString("password")

		data := make(map[string]interface{})
		data["code"] = defined.SUCCESS

		a := auth{
			Username: username,
			Password: password,
		}

		err := Validator.Struct(&a)
		if err != nil {
			data["code"] = defined.ERR_AUTH
		}

		exist := jp.check_handle(username, password)
		if exist {
			token, err := jp.GenerateToken(username, password)
			if err != nil {
				data["code"] = defined.ERR_AUTH_GENERATE
			} else {
				data["token"] = token
				data["code"] = defined.SUCCESS
			}
		} else {
			data["code"] = defined.ERR_AUTH
		}

		jp.res_handle(ctx, data)
	}
}

// middler check auth.
func (jp *JWTPass) MiddlerAuth() gnet.HandleFunc {
	return func(ctx gnet.Contexter) {
		data := make(map[string]interface{})
		code := defined.SUCCESS
		token, _ := ctx.Request().GetString("token")
		link.DEBUG_PRINT("[JWT][MIDDLER][AUTH]", token)
		if token == "" {
			code = defined.ERROR_AUTH_CHECK_TOKEN_FAIL
		} else {
			claims, err := jp.ParseToken(token)
			if err != nil {
				code = defined.ERROR_AUTH_CHECK_TOKEN_FAIL
				goto WALK
			}
			if time.Now().Unix() > claims.ExpiresAt {
				code = defined.ERROR_AUTH_CHECK_TOKEN_TIMEOUT
				goto WALK
			}
		}

	WALK:
		data["code"] = code

		if code == defined.SUCCESS {
			return
		}
		jp.res_handle(ctx, data)
		ctx.Exit()
	}
}
