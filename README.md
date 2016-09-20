# miller

Package miller implements tamper resistant message signing and verification.

## Usage

The default tag is used for this example. Tags can be used to namespace your
tokens. For example, if you issue account confirmation and recovery tokens,
different tags can be used so that confirmation tokens cannot be used for
account recovery.

```go
t := miller.New(miller.DefaultTag, []byte("secret"))
token, err := t.Sign("foo")
if err != nil {
  log.Fatal(err)
}
var s string
err = t.Verify(token, &s)
if err != nil {
  log.Fatal(err)
}
// s == "foo"
```
