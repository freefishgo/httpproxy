package main

import (
	"bytes"
	"fmt"
	"github.com/freefishgo/httpproxy"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	// Log errors.
	log.Printf("ERR: %s: %s [%s]", where, err, opErr)
}

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	// Handle local request has path "/info"
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is go-httpproxy."))
		return true
	}
	return false
}

func OnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
	// Auth test user.
	if user == "test" && pass == "test" {
		return true
	}
	return false
}

func OnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	// Apply "Man in the Middle" to all ssl connections. Never change host.
	//if strings.Contains(host, ":8098") {
	//	return httpproxy.ConnectMitm, host
	//}
	//return httpproxy.ConnectMitm, host
	return httpproxy.ConnectProxy, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	// Log proxying requests.
	//req.RequestURI = ""
	log.Printf("INFO: Proxy: %s %s", req.Method, req.URL.String())
	//resp, err := HTTPGet(req)
	//if err != nil {
	//	log.Printf("err: %s", err.Error())
	//}
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	//&& strings.Contains(req.URL.Path, "/douyin-system/api/buyin/card/users/validate/")
	if strings.Contains(req.Host, "yanzhen.sxkstg.cn:8098") {
		// Add header "Via: go-httpproxy".
		b, _ := io.ReadAll(resp.Body)
		html := string(b)
		if strings.Contains(req.URL.Path, "/douyin-system/api/buyin/card/users/validate") {
			html = `{"success": true,"message": "HMvD+/l0roiqz/K8S63NS5UkI++LEt/uWR/3ve5bkxooe2DbQfNzqvWRWty1+lYu","code": 0,"result": null,"timestamp": %d}`
		} else if strings.Contains(req.URL.Path, "/douyin-system/api/buyin/exception/add") {
			html = `{"success":true,"message":"操作成功","code":200,"result":"操作成功","timestamp":%d}`
		} else if strings.Contains(req.URL.Path, "/douyin-system/api/buyin/card/activationCardNo") {
			html = `{"success": true,"message": "HMvD+/l0roiqz/K8S63NS5UkI++LEt/uWR/3ve5bkxooe2DbQfNzqvWRWty1+lYu","code": 0,"result": null,"timestamp": %d}`
		}
		html = fmt.Sprintf(html, time.Now().UnixMilli())
		body := io.NopCloser(bytes.NewBuffer([]byte(html)))
		resp.Body = body
		resp.ContentLength = int64(len(html))
		log.Printf("INFO: Proxy: %s %s", req.Method, req.URL.String())
	} else {
		//resp.Body = io.NopCloser(bytes.NewBuffer(b))
	}
}

// HTTPGet localIP是网卡IP
func HTTPGet(req *http.Request) (*http.Response, error) {
	//req, _ := http.NewRequest("GET", url, nil)
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				// localIP 网卡IP，":0" 表示端口自动选择
				localIP := "192.168.30.38"
				lAddr, err := net.ResolveTCPAddr(netw, localIP+":0")
				if err != nil {
					return nil, err
				}

				rAddr, err := net.ResolveTCPAddr(netw, addr)
				if err != nil {
					return nil, err
				}
				conn, err := net.DialTCP(netw, lAddr, rAddr)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		},
	}
	return client.Do(req)
}

func main() {
	//localIP := "192.168.30.38"
	//net.DefaultResolver = &net.Resolver{
	//	PreferGo: true,
	//	//StrictErrors: true,
	//	Dial: func(ctx context.Context, netw, addr string) (net.Conn, error) {
	//		//if strings.HasPrefix(addr, "127.0.0.1") {
	//		//	addr = strings.Replace(addr, "127.0.0.1", localIP, 1)
	//		//	//return nil, nil
	//		//}
	//		if netw == "tcp" {
	//			lAddr, err := net.ResolveTCPAddr(netw, localIP+":0")
	//			if err != nil {
	//				return nil, err
	//			}
	//
	//			rAddr, err := net.ResolveTCPAddr(netw, addr)
	//			if err != nil {
	//				return nil, err
	//			}
	//			conn, err := net.DialTCP(netw, lAddr, rAddr)
	//			if err != nil {
	//				return nil, err
	//			}
	//			return conn, nil
	//		}
	//		return net.Dial(netw, addr)
	//	},
	//}
	prx, _ := httpproxy.NewProxy()
	ca, _ := os.ReadFile("ca_cert.pem")
	pra, _ := os.ReadFile("ca_key.pem")
	prx, _ = httpproxy.NewProxyCert(ca, pra)
	// Set handlers.
	prx.OnError = OnError
	prx.OnAccept = OnAccept
	//prx.OnAuth = OnAuth
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse

	// Listen...
	http.ListenAndServe(":9090", prx)
}
