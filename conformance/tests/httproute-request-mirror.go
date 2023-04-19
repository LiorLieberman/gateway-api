/*
Copyright 2023 The Kubernetes Authors.

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

package tests

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteRequestMirror)
}

var HTTPRouteRequestMirror = suite.ConformanceTest{
	ShortName:   "HTTPRouteRequestMirror",
	Description: "An HTTPRoute with request mirror filter",
	Manifests:   []string{"tests/httproute-request-mirror.yaml"},
	// Features: []suite.SupportedFeature{
	// 	suite.SupportGateway,
	// 	suite.SupportHTTPRoute,
	// 	suite.SupportHTTPRouteRequestMirror,
	// },
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "request-mirror", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		testCases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Path: "/mirror",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/mirror",
					},
				},
				Backend:    "infra-backend-v1",
				MirroredTo: "mirrored-backend-1",
				Namespace:  ns,
			},
		}
		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
				if tc.MirroredTo == "" {
					t.Fatalf("MirroredTo wasn't provided in the testcase, this test should only check http request mirror.")
				}
				http.ExpectMirroredRequest(t, suite.Client, suite.Clientset, ns, tc.MirroredTo, tc.Request.Path)
			})
		}
	},
}
