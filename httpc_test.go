package httpc

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

var testRequests = map[*Request]func(resp *http.Response) error{
	New("GET", "http://127.0.0.1:22632/foo"): func(resp *http.Response) error {
		return nil
	},
}

func TestTable(t *testing.T) {
	for k, v := range testRequests {
		t.Run(fmt.Sprintf("%s %s", k.method, k.uri), func(t *testing.T) {
			err := k.ParseFn(v).Run()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestMain(m *testing.M) {

	// the corresponding fasthttp code
	server := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/foo":
			fooHandlerFunc(ctx)
		// case "/bar":
		// 	barHandlerFunc(ctx)
		default:
			ctx.Error("not found", fasthttp.StatusNotFound)
		}
	}

	// Start test server
	go func() {
		if err := fasthttp.ListenAndServe("127.0.0.1:22632", server); err != nil {
			fmt.Printf("Failed to start test server: %s\n", err)
			os.Exit(1)
		}
	}()

	var err error
	for try := 0; try < 10; try++ {
		_, err = net.DialTimeout("tcp", "127.0.0.1:22632", time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Printf("Connectivity test failed: %s\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func fooHandlerFunc(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hello, world!\n\n")
	ctx.SetContentType("text/plain; charset=utf8")
}

// func echoHandlerFunc(ctx *fasthttp.RequestCtx) {
// 	fmt.Fprintf(ctx, ctx.Request.Body())
// 	ctx.SetContentType("text/plain; charset=utf8")
// }
