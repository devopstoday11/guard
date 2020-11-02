package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//GrumpyServerHandler listen to admission requests and serve responses
type GrumpyServerHandler struct {
}

func (gs *GrumpyServerHandler) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	glog.Info("Received request")

	if r.URL.Path != "/validate" {
		glog.Error("no validate")
		http.Error(w, "no validate", http.StatusBadRequest)
		return
	}

	arRequest := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(body, &arRequest); err != nil {
		glog.Error("incorrect body")
		http.Error(w, "incorrect body", http.StatusBadRequest)
	}

	raw := arRequest.Request.Object.Raw
	pod := v1.Pod{}
	if err := json.Unmarshal(raw, &pod); err != nil {
		glog.Error("error deserializing pod")
		return
	}
	if pod.Name == "smooth-app" {
		return
	}

	for k, v := range pod.Annotations {
		if k == "devtron.ai.cd-validated" {
			if v != "" {
				//decode and match signature in the image
				return
			}
		}
		if k == "devtron.ai.cd-exception" {
			if v != "" {
				//check authenticity of exception
				return
			}
		}
	}
	var images []string
	for _, container := range pod.Spec.Containers {
		images = append(images, container.Image)
	}
	releaseName := ""
	for k, v := range pod.Labels {
		if k == "release" {
			releaseName = v
		}
	}
	glog.Info("Labels ", pod.Labels)
	glog.Info("releaseName", releaseName)
	verificationResponse, err := verifyImage(images, releaseName, pod.Namespace)
	if err != nil {
		glog.Error(err)
	}
	arResponse := v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			Allowed: verificationResponse.allowed,
			Result: &metav1.Status{
				Message: verificationResponse.msg,
			},
		},
	}
	resp, err := json.Marshal(arResponse)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

type VerificationResponse struct {
	allowed bool
	msg     string
}

/*
1. get environment name by ns+ cluster
2. appName = releaseName - environmentName
3. verify app-env-image combination is correct
4. get policy for app(global, cluster, env, app)
5. get vulnblity for image
6. apply policy

if releaseName is empty(unable to determine app name) get policy for environment,
*/

/*
while deploying apply policy check annotation
*/
func verifyImage(images []string, releaseName string, namespace string) (*VerificationResponse, error) {
	//clusterName := "default_cluster"
	glog.Info("verify req", images, releaseName, namespace, ClusterName)
	validator, err := NewValidatorClientImpl(strings.TrimSpace(*ValidatorUrl))
	if err != nil {
		glog.Error("err", err)
	}
	r, err := validator.VerifyImages(&VerifyImageRequest{
		Images:      images,
		ReleaseName: releaseName,
		Namespace:   namespace,
		ClusterName: *ClusterName,
	})
	if err != nil {
		glog.Error("err2", err)
	}
	allowed := true
	var cves []string
	for _, imagePolicy := range r {
		if len(imagePolicy) > 0 {
			allowed = false
		}
		for _, cve := range imagePolicy {
			cves = append(cves, cve.Name)
		}
	}
	msg := "blocked CVE " + strings.Join(cves, " , ")
	fmt.Println(r)
	verificationResponse := &VerificationResponse{allowed: allowed, msg: msg}
	glog.Info("verification response ", verificationResponse)
	return verificationResponse, nil
}
