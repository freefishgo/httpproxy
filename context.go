package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Context keeps context of each proxy request.
type Context struct {
	// Pointer of Proxy struct handled this context.
	// It's using internally. Don't change in Context struct!
	Prx *Proxy

	// Session number of this context obtained from Proxy struct.
	SessionNo int64

	// Sub session number of processing remote connection.
	SubSessionNo int64

	// Original Proxy request.
	// It's using internally. Don't change in Context struct!
	Req *http.Request

	// Original Proxy request, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectReq *http.Request

	// Action of after the CONNECT, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectAction ConnectAction

	// Remote host, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectHost string

	// User data to use free.
	UserData interface{}

	hijTLSConn   *tls.Conn
	hijTLSReader *bufio.Reader
}

func (ctx *Context) onAccept(w http.ResponseWriter, r *http.Request) bool {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Accept", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAccept(ctx, w, r)
}

func (ctx *Context) onAuth(authType string, user string, pass string) bool {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Auth", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAuth(ctx, authType, user, pass)
}

func (ctx *Context) onConnect(host string) (ConnectAction ConnectAction,
	newHost string) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Connect", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnConnect(ctx, host)
}

func (ctx *Context) onRequest(req *http.Request) (resp *http.Response) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Request", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnRequest(ctx, req)
}

func (ctx *Context) onResponse(req *http.Request, resp *http.Response) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Response", ErrPanic, err)
		}
	}()
	ctx.Prx.OnResponse(ctx, req, resp)
}

func (ctx *Context) doError(where string, err *Error, opErr error) {
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, where, err, opErr)
}

func (ctx *Context) doAccept(w http.ResponseWriter, r *http.Request) bool {
	ctx.Req = r
	if !r.ProtoAtLeast(1, 0) || r.ProtoAtLeast(2, 0) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Accept", ErrNotSupportHTTPVer, nil)
		return true
	}
	if ctx.Prx.OnAccept != nil && ctx.onAccept(w, r) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		return true
	}
	return false
}

func (ctx *Context) doAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "CONNECT" && !r.URL.IsAbs() {
		return false
	}
	if ctx.Prx.OnAuth == nil {
		return false
	}
	prxAuthType := ctx.Prx.AuthType
	if prxAuthType == "" {
		prxAuthType = "Basic"
	}
	unauthorized := false
	authParts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authParts) >= 2 {
		authType := authParts[0]
		authData := authParts[1]
		if prxAuthType == authType {
			unauthorized = true
			switch authType {
			case "Basic":
				userpassraw, err := base64.StdEncoding.DecodeString(authData)
				if err == nil {
					userpass := strings.SplitN(string(userpassraw), ":", 2)
					if len(userpass) >= 2 && ctx.onAuth(authType, userpass[0], userpass[1]) {
						return false
					}
				}
			default:
				unauthorized = false
			}
		}
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	respCode := 407
	respBody := "Proxy Authentication Required"
	if unauthorized {
		respBody += " [Unauthorized]"
	}
	err := ServeInMemory(w, respCode, map[string][]string{"Proxy-Authenticate": {prxAuthType}},
		[]byte(respBody))
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Auth", ErrResponseWrite, err)
	}
	return true
}

func GetOutBoundIP() (ip string, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println(err)
		return
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip = strings.Split(localAddr.String(), ":")[0]
	return
}

var localIP = ""

func init() {
	var err error
	localIP, err = GetOutBoundIP()
	if err != nil {
		panic(err)
	}
	log.Println("localIP:", localIP)
}

var dial = func(netw, addr string) (net.Conn, error) {
	// localIP 网卡IP，":0" 表示端口自动选择
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
}

func (ctx *Context) doConnect(w http.ResponseWriter, r *http.Request) (b bool) {
	b = true
	if r.Method != "CONNECT" {
		b = false
		return
	}
	if strings.Contains(r.URL.Host, ":8098") {
		w.Write([]byte("随便写写"))
		b = false
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, nil)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, err)
		return
	}
	hijConn := conn
	ctx.ConnectReq = r
	ctx.ConnectAction = ConnectProxy
	host := r.URL.Host
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	if ctx.Prx.OnConnect != nil {
		var newHost string
		ctx.ConnectAction, newHost = ctx.onConnect(host)
		if newHost != "" {
			host = newHost
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	ctx.ConnectHost = host
	switch ctx.ConnectAction {
	case ConnectProxy:

		//conn, err := net.Dial("tcp", host)
		conn, err := dial("tcp", host)
		if err != nil {
			hijConn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
			hijConn.Close()
			ctx.doError("Connect", ErrRemoteConnect, err)
			return
		}
		remoteConn := conn.(*net.TCPConn)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			remoteConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
			}
			return
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) {
					ctx.doError("Connect", ErrRequestRead, err)
				}
			}()
			_, err := io.Copy(remoteConn, hijConn)
			if err != nil {
				panic(err)
			}
			remoteConn.CloseWrite()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseRead()
			}
		}()
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) {
					ctx.doError("Connect", ErrResponseWrite, err)
				}
			}()
			_, err := io.Copy(hijConn, remoteConn)
			if err != nil {
				panic(err)
			}
			remoteConn.CloseRead()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
		}()
		wg.Wait()
		hijConn.Close()
		remoteConn.Close()
	case ConnectMitm:
		tlsConfig := &tls.Config{}
		cert := ctx.Prx.signer.SignHost(host)
		if cert == nil {
			hijConn.Close()
			ctx.doError("Connect", ErrTLSSignHost, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
			}
			return
		}
		ctx.hijTLSConn = tls.Server(hijConn, tlsConfig)

		if err := ctx.hijTLSConn.Handshake(); err != nil {
			ctx.hijTLSConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrTLSHandshake, err)
			}
			return
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.hijTLSConn)
		b = false
	default:
		hijConn.Close()
	}
	return
}

// HTTPGet localIP是网卡IP
func HTTPGet(req *http.Request) (*http.Response, error) {
	//req, _ := http.NewRequest("GET", url, nil)
	client := &http.Client{
		Transport: &http.Transport{
			Dial: dial,
		},
	}
	return client.Do(req)
}

func (ctx *Context) doMitm() (w http.ResponseWriter, r *http.Request) {
	req, err := http.ReadRequest(ctx.hijTLSReader)
	if err != nil {
		if !isConnectionClosed(err) {
			ctx.doError("Request", ErrRequestRead, err)
		}
		return
	}
	req.RemoteAddr = ctx.ConnectReq.RemoteAddr
	if req.URL.IsAbs() {
		ctx.doError("Request", ErrAbsURLAfterCONNECT, nil)
		return
	}
	req.URL.Scheme = "https"
	//req.URL.Scheme = "http"
	req.URL.Host = ctx.ConnectHost
	w = NewConnResponseWriter(ctx.hijTLSConn)
	r = req
	return
}

func (ctx *Context) doRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	if !r.URL.IsAbs() {
		if r.Body != nil {
			defer r.Body.Close()
		}
		fmt.Println(r.URL.Path)
		//err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		w.Header().Set("Content-Type", "text/json")
		html := ""
		if strings.Contains(r.URL.Path, "/douyin-system/api/buyin/card/users/validate") {
			w.Header().Set("Content-Type", "text/json")
			html = `{"success": true,"message": "HMvD+/l0roiqz/K8S63NS5UkI++LEt/uWR/3ve5bkxooe2DbQfNzqvWRWty1+lYu","code": 0,"result": null,"timestamp": %d}`
			html = fmt.Sprintf(html, time.Now().UnixMilli())
		} else if strings.Contains(r.URL.Path, "/douyin-system/api/buyin/exception/add") {
			//req, _ := http.NewRequest(http.MethodPost, "http://"+r.Host+"/douyin-system/api/buyin/exception/add", r.Body)
			//req.Header.Set("Content-Type", "application/json")
			//resp, err := HTTPGet(req)
			//if err != nil {
			//	fmt.Println(err.Error())
			//	panic(err)
			//}
			//defer resp.Body.Close()
			//b, _ := io.ReadAll(resp.Body)
			//html = string(b)
			//w.Header().Set("Content-Type", "text/json")
			html = `{"success":true,"message":"操作成功","code":200,"result":"操作成功","timestamp":%d}`
			html = fmt.Sprintf(html, time.Now().UnixMilli())
		} else if strings.Contains(r.URL.Path, "/douyin-system/api/buyin/card/activationCardNo") {
			w.Header().Set("Content-Type", "text/json")
			html = `{"success":true,"message":"","code":200,"result":{"card_no":"aQU5CU6JRZQV36Fy1a6E","expiration_time":"%s","id":"1708363025479168002"},"timestamp":1696228237381}`
			html = `{"success":true,"message":"","code":200,"result":{"card_no":"%s","expiration_time":"%s","id":"1708363025479168002"},"timestamp":%d}`
			html = fmt.Sprintf(html, r.Header.Get("Card_no"), time.Now().AddDate(0, 1, 1).Format("2006-01-02 15:04:05"), time.Now().Unix())
		} else if strings.Contains(r.URL.Path, "/douyin-system/api/common/static2/upgrade/config.xml") {
			//w.Header().Set("Content-Type","text/xml")
			req, _ := http.NewRequest(http.MethodGet, "http://"+r.Host+"/douyin-system/api/common/static2/upgrade/config.xml", nil)
			resp, err := HTTPGet(req)
			if err != nil {
				fmt.Println(err.Error())
				panic(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			html = string(b)
		} else if strings.Contains(r.URL.Path, "/douyin-system/api/buyin/card/unBindLicenses") {
			html = `{"success":true,"message":"操作成功","code":200,"result":"操作成功","timestamp":1696228237381}`
		} else if strings.Contains(r.URL.Path, "/douyin-system/api/buyin/card/updateStatus") {

		} else {
			if r.Method != http.MethodConnect {
				req, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.Path, r.Body)
				if r.Header.Get("Content-Type") != "" {
					req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
				}
				resp, err := HTTPGet(req)
				if err != nil {
					fmt.Println(err.Error())
					panic(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				html = string(b)
				if r.Header.Get("Content-Type") != "" {
					w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
				}
			}
		}
		err := ServeInMemory(w, 200, nil, []byte(html))
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Request", ErrResponseWrite, err)
		}
		return true, err
	}
	r.RequestURI = r.URL.String()
	if ctx.Prx.OnRequest == nil {
		return false, nil
	}
	resp := ctx.onRequest(r)
	if resp == nil {
		return false, nil
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err := ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Request", ErrResponseWrite, err)
	}
	return true, err
}

func (ctx *Context) doResponse(w http.ResponseWriter, r *http.Request) error {
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) {
			ctx.doError("Response", ErrRoundTrip, err)
		}
		err := ServeInMemory(w, 404, nil, nil)
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Response", ErrResponseWrite, err)
		}
		return err
	}
	if ctx.Prx.OnResponse != nil {
		ctx.onResponse(r, resp)
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Response", ErrResponseWrite, err)
	}
	return err
}
