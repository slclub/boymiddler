# boymiddler
middlers of boy

Jwt secret login and validate auth.

## Listing

- [JWTPass(encryption secret)](#j-w-t-pass)
  - [LoginWithToken](#login-with-token)
  - [AutoToken](#auth-token)

## Coding

An simple demo.  How to login and verify with jwt.

```go
import (
    "github.com/slclub/boy"
    "github.com/slclub/boymiddler"
    "github.com/slclub/gnet"
    "github.com/slclub/grouter"
)

func main() {

    auth := boymiddler.NewJWTPass()
    auth.SetCheckHandle(func(user, pass string) bool {
        // select from database by user and pass. Judge whether the user exists
        return true
    })
    // Response data
    // The default response handle.
    auth.SetResponseHandle(func(ctx gnet.Contexter, data map[string]interface{}) {
        ctx.Data(data).Echo()
    })

    // Use middler before node validate auth.
    //boy.MiddlerBefore.Use(auth.MiddlerAuth())

    //  Using routing middlerware directly.                                                                                                                                                                                     
    grouter.Group.Use(auth.MiddlerAuth())

    // login and create token.
    boy.R.GET("/login/:username/:password", auth.AuthHandle())

    boy.Run()
}


```

## JWTPass

### LoginWithToken

Login and generate jwt token.

```go
auth := boymiddler.NewJWTPass()
auth.SetCheckHandle(func(user, pass string) bool {
    // select from database by user and pass. Judge whether the user exists
    return true
})
// Response data
// The default response handle.
auth.SetResponseHandle(func(ctx gnet.Contexter, data map[string]interface{}) {
    ctx.Data(data).Echo()
})
// gnet.HandleFunc
auth.AuthHandle()
```

### AuthToken

- Use middleware(before node) to verify.

```go
    // Use middler before node validate auth.
    boy.MiddlerBefore.Use(auth.MiddlerAuth())
```

-  Use router middleware() to verify.

```go
    //  Using routing middlerware directly.                                                                                                                                                                                     
    grouter.Group.Use(auth.MiddlerAuth())
```
