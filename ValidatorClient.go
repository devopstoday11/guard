package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"time"
)

type ValidatorClientImpl struct {
	httpClient *http.Client
	//logger     *zap.SugaredLogger
	baseUrl *url.URL
}

func NewValidatorClientImpl(baseUrls string) (session *ValidatorClientImpl, err error) {
	baseUrl, err := url.Parse(baseUrls)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	return &ValidatorClientImpl{httpClient: client, baseUrl: baseUrl}, nil
}

type StatusCode int

func (code StatusCode) IsSuccess() bool {
	return code >= 200 && code <= 299
}

type ClientRequest struct {
	Method       string
	Path         string
	RequestBody  interface{}
	ResponseBody interface{}
}

func (session *ValidatorClientImpl) doRequest(clientRequest *ClientRequest) (resBody []byte, resCode *StatusCode, err error) {
	if clientRequest.ResponseBody == nil {
		return nil, nil, fmt.Errorf("responce body cant be nil")
	}
	if reflect.ValueOf(clientRequest.ResponseBody).Kind() != reflect.Ptr {
		return nil, nil, fmt.Errorf("responsebody non pointer")
	}
	rel, err := session.baseUrl.Parse(clientRequest.Path)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println(clientRequest.RequestBody)
	var body io.Reader
	if clientRequest.RequestBody != nil {
		if req, err := json.Marshal(clientRequest.RequestBody); err != nil {
			return nil, nil, err
		} else {
			//session.logger.Infow("argo req with body", "body", string(req))
			fmt.Println(string(req))
			body = bytes.NewBuffer(req)
		}

	}
	httpReq, err := http.NewRequest(clientRequest.Method, rel.String(), body)
	if err != nil {
		return nil, nil, err
	}
	dump, err:=httputil.DumpRequest(httpReq, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP request %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "----> HTTP REQUEST:\n%s\n", string(dump[:]))
	}
	httpRes, err := session.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer httpRes.Body.Close()
	dump, err=httputil.DumpResponse(httpRes, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP request %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "----> HTTP REQUEST:\n%s\n", string(dump[:]))
	}
	resBody, err = ioutil.ReadAll(httpRes.Body)
	if err != nil {
		//session.logger.Errorw("error in argocd communication ", "err", err)
		return nil, nil, err
	}

	status := StatusCode(httpRes.StatusCode)
	if status.IsSuccess() {
		apiRes := make(map[string]interface{})
		err = json.Unmarshal(resBody, &apiRes)
		fmt.Println(apiRes)
		/*if apiStatus := StatusCode(apiRes.Code); apiStatus.IsSuccess() {
			err = json.Unmarshal(apiRes.Result, clientRequest.ResponseBody)
			return resBody, &apiStatus, err
		} else {
			session.logger.Infow("api err", "res", apiRes.Errors)
			return resBody, &apiStatus, fmt.Errorf("err in api res")
		}*/
	} else {
		//session.logger.Infow("api err", "res", string(resBody))
		return resBody, &status, fmt.Errorf("res not success, code: %d ", status)
	}
	return resBody, &status, err
}

type VerifyImageRequest struct {
	Images      []string
	ReleaseName string
	Namespace   string
	ClusterName string
}

type VerifyImageResponse struct {
	Name         string
	Severity     string
	Package      string
	Version      string
	FixedVersion string
}

func (session ValidatorClientImpl) VerifyImages(req *VerifyImageRequest) (material map[string][]*VerifyImageResponse, err error) {
	request := &ClientRequest{ResponseBody: &material, Method: "POST", RequestBody: req, Path: "/security/policy/verify/webhook"}
	_, _, err = session.doRequest(request)
	return material, err
}
