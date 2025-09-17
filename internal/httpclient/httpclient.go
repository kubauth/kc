/*
Copyright 2025 Kubotal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"kc/internal/misc"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type HttpAuth struct {
	Login    string
	Password string
	Token    string
}

type Config struct {
	BaseURL            string
	RootCaPaths        []string
	RootCaDatas        []string
	InsecureSkipVerify bool
	DumpExchanges      bool
}

func New(conf *Config) (*http.Client, error) {
	// Just a test for validity. Not used in this function
	u, err := url.Parse(conf.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url '%s': %w", conf.BaseURL, err)
	}
	if strings.ToLower(u.Scheme) != "https" && strings.ToLower(u.Scheme) != "http" {
		return nil, fmt.Errorf("invalid url scheme '%s'", conf.BaseURL)
	}
	var tlsConfig *tls.Config = nil
	if strings.ToLower(u.Scheme) == "https" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{RootCAs: pool, InsecureSkipVerify: conf.InsecureSkipVerify}
		if !conf.InsecureSkipVerify {
			caCount := 0
			for _, rootCaPath := range conf.RootCaPaths {
				if rootCaPath != "" {
					if err := appendCaFromFile(tlsConfig.RootCAs, rootCaPath); err != nil {
						return nil, err
					}
					caCount++
				}
			}
			for _, rootCaData := range conf.RootCaDatas {
				if rootCaData != "" {
					if err := appendCaFromBase64(tlsConfig.RootCAs, rootCaData); err != nil {
						return nil, err
					}
					caCount++
				}
			}
			//if caCount == 0 {
			//	return nil, fmt.Errorf("no root CA certificate was configured")
			//}
		}
	}
	httpclient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	if conf.DumpExchanges {
		httpclient.Transport = debugTransport{httpclient.Transport}
	}
	return httpclient, nil
}

func appendCaFromFile(pool *x509.CertPool, caPath string) error {
	rootCaBytes, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("failed to read CA file '%s': %w", caPath, err)
	}
	if !pool.AppendCertsFromPEM(rootCaBytes) {
		return fmt.Errorf("invalid root CA certificate in file %s", caPath)
	}
	return nil
}

func appendCaFromBase64(pool *x509.CertPool, b64 string) error {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	_, err := base64.StdEncoding.Decode(data, []byte(b64))
	if err != nil {
		return fmt.Errorf("error while parsing base64 root ca data %s : %w", misc.ShortenString(b64), err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("invalid root CA certificate in %s", misc.ShortenString(b64))
	}
	return nil
}

type debugTransport struct {
	t http.RoundTripper
}

var exchangeCount = 0

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	fmt.Printf("-----------------> REQUEST (%d)\n%s\n----------------->\n", exchangeCount, string(reqDump))
	exchangeCount++
	//log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	fmt.Printf("<----------------- RESPONSE (%d)\n%s\n<-----------------\n", exchangeCount, string(respDump))
	exchangeCount++
	//log.Printf("%s", respDump)
	return resp, nil
}
