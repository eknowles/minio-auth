package main_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/plugin"
)

func TestMinioAuth(t *testing.T) {
	// Create a mock Traefik middleware config
	middlewareConfig := &dynamic.Middleware{
		Config: map[string]interface{}{
			"accessKey": "minio-access-key",
			"secretKey": "minio-secret-key",
		},
	}

	// Create the MinioAuth handler
	handler, err := CreateMinioAuth(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), middlewareConfig)
	if err != nil {
		t.Errorf("CreateMinioAuth returned an error: %v", err)
	}

	// Create a test request
	req, err := http.NewRequest("GET", "/minio/bucket/object", nil)
	if err != nil {
		t.Errorf("Failed to create test request: %v", err)
	}

	// Wrap the request with the MinioAuth handler
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the added headers
	if rr.Header().Get(xAmzAlgorithm) != awsV4Algorithm {
		t.Errorf("Expected %s header to be %s, got %s", xAmzAlgorithm, awsV4Algorithm, rr.Header().Get(xAmzAlgorithm))
	}

	if rr.Header().Get(xAmzCredential) != "minio-access-key/2023/04/13/us-east-1/s3/aws4_request" {
		t.Errorf("Expected %s header to be %s, got %s", xAmzCredential, "minio-access-key/2023/04/13/us-east-1/s3/aws4_request", rr.Header().Get(xAmzCredential))
	}

	if rr.Header().Get(xAmzDate) == "" {
		t.Errorf("Expected %s header to be set", xAmzDate)
	}

	if rr.Header().Get(xAmzSignature) == "" {
		t.Errorf("Expected %s header to be set", xAmzSignature)
	}
}

func TestGenerateMinioHeaders(t *testing.T) {
	accessKey := "minio-access-key"
	secretKey := "minio-secret-key"
	method := "GET"
	path := "/minio/bucket/object"
	queryParams := url.Values{
		"param1": []string{"value1"},
		"param2": []string{"value2", "value3"},
	}

	headers, err := generateMinioHeaders(accessKey, secretKey, method, path, queryParams)
	if err != nil {
		t.Errorf("generateMinioHeaders returned an error: %v", err)
	}

	if headers[xAmzAlgorithm] != awsV4Algorithm {
		t.Errorf("Expected %s header to be %s, got %s", xAmzAlgorithm, awsV4Algorithm, headers[xAmzAlgorithm])
	}

	if headers[xAmzCredential] != "minio-access-key/2023/04/13/us-east-1/s3/aws4_request" {
		t.Errorf("Expected %s header to be %s, got %s", xAmzCredential, "minio-access-key/2023/04/13/us-east-1/s3/aws4_request", headers[xAmzCredential])
	}

	if headers[xAmzDate] == "" {
		t.Errorf("Expected %s header to be set", xAmzDate)
	}

	if headers[xAmzSignature] == "" {
		t.Errorf("Expected %s header to be set", xAmzSignature)
	}
}

func TestFormatQueryString(t *testing.T) {
	queryParams := url.Values{
		"param1": []string{"value1"},
		"param2": []string{"value2", "value3"},
	}

	formattedQuery := formatQueryString(queryParams)
	expected := "param1=value1&param2=value2,value3"
	if formattedQuery != expected {
		t.Errorf("Expected formatted query string to be %s, got %s", expected, formattedQuery)
	}
}

func TestHashSHA256(t *testing.T) {
	data := []byte("test data")
	hash, err := hashSHA256(data)
	if err != nil {
		t.Errorf("hashSHA256 returned an error: %v", err)
	}

	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if hash != expected {
		t.Errorf("Expected SHA-256 hash to be %s, got %s", expected, hash)
	}
}

func TestCalculateSignature(t *testing.T) {
	secretKey := "minio-secret-key"
	date := "20230413"
	region := "us-east-1"
	service := "s3"
	stringToSign := "AWS4-HMAC-SHA256\n20230413\n2023/04/13/us-east-1/s3/aws4_request\n9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	signature, err := calculateSignature(secretKey, date, region, service, stringToSign)
	if err != nil {
		t.Errorf("calculateSignature returned an error: %v", err)
	}

	expected := "e5154ffea8cf778da9b5d5613ed74d6685d1e7e97460b25cbe7c31fa49dd5e3f"
	if signature != expected {
		t.Errorf("Expected signature to be %s, got %s", expected, signature)
	}
}

func TestGetSigningKey(t *testing.T) {
	secretKey := "minio-secret-key"
	date := "20230413"
	region := "us-east-1"
	service := "s3"

	signingKey, err := getSigningKey(secretKey, date, region, service)
	if err != nil {
		t.Errorf("getSigningKey returned an error: %v", err)
	}

	expected := "fc4f00d9f5bd944f1bccf7f7087d2b79e04e7d1c22de295d05a1c17b154e4d7"
	if signingKey != expected {
		t.Errorf("Expected signing key to be %s, got %s", expected, signingKey)
	}
}

func TestPluginRegister(t *testing.T) {
	// Ensure the plugin is registered correctly
	_, err := plugin.Get("minio-auth")
	if err != nil {
		t.Errorf("Plugin 'minio-auth' is not registered: %v", err)
	}
}
