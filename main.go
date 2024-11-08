package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/plugin"
)

const (
	xAmzAlgorithm  = "X-Amz-Algorithm"
	xAmzCredential = "X-Amz-Credential"
	xAmzDate       = "X-Amz-Date"
	xAmzSignature  = "X-Amz-Signature"
	awsV4Algorithm = "AWS4-HMAC-SHA256"
	awsServiceName = "s3"
	awsRegion      = "us-east-1" // Replace with your Minio region
)

type Config struct {
	AccessKey string
	SecretKey string
}

type MinioAuth struct {
	next   http.Handler
	config *Config
}

func CreateMinioAuth(ctx context.Context, next http.Handler, config *dynamic.Middleware) (http.Handler, error) {
	cfg := &Config{
		AccessKey: config.Config["accessKey"].(string),
		SecretKey: config.Config["secretKey"].(string),
	}

	return &MinioAuth{
		next:   next,
		config: cfg,
	}, nil
}

func (a *MinioAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Generate Minio authentication headers
	headers, err := generateMinioHeaders(a.config.AccessKey, a.config.SecretKey, req.Method, req.URL.Path, req.URL.Query())
	if err != nil {
		// Handle error
		return
	}

	// Add the headers to the request
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	a.next.ServeHTTP(rw, req)
}

func generateMinioHeaders(accessKey, secretKey, method, path string, queryParams url.Values) (map[string]string, error) {
	requestDate := time.Now().UTC().Format("20060102T150405Z")

	// Construct the canonical request
	canonicalRequest := strings.Join([]string{
		method,
		path,
		formatQueryString(queryParams),
		xAmzDate + ":" + requestDate + "\n",
		"",
		xAmzDate + ":" + requestDate,
	}, "\n")
	canonicalRequestHash, err := hashSHA256([]byte(canonicalRequest))
	if err != nil {
		return nil, err
	}

	// Calculate the AWS Signature Version 4 (SIGv4) signature
	credentialScope := strings.Join([]string{
		requestDate[:8],
		awsRegion,
		awsServiceName,
		"aws4_request",
	}, "/")
	stringToSign := strings.Join([]string{
		awsV4Algorithm,
		requestDate,
		credentialScope,
		canonicalRequestHash,
	}, "\n")
	signature, err := calculateSignature(secretKey, requestDate[:8], awsRegion, awsServiceName, stringToSign)
	if err != nil {
		return nil, err
	}

	// Construct the headers
	headers := map[string]string{
		xAmzAlgorithm:  awsV4Algorithm,
		xAmzCredential: accessKey + "/" + credentialScope,
		xAmzDate:       requestDate,
		xAmzSignature:  signature,
	}

	return headers, nil
}

func formatQueryString(queryParams url.Values) string {
	var parts []string
	for k, v := range queryParams {
		parts = append(parts, k+"="+strings.Join(v, ","))
	}
	return strings.Join(parts, "&")
}

func hashSHA256(data []byte) (string, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func calculateSignature(secretKey, date, region, service, stringToSign string) (string, error) {
	signingKey, err := getSigningKey(secretKey, date, region, service)
	if err != nil {
		return "", err
	}
	signature := hmac.New(sha256.New, []byte(signingKey))
	_, err = signature.Write([]byte(stringToSign))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature.Sum(nil)), nil
}

func getSigningKey(secretKey, date, region, service string) (string, error) {
	kDate := hmac.New(sha256.New, []byte("AWS4"+secretKey))
	_, err := kDate.Write([]byte(date))
	if err != nil {
		return "", err
	}
	kRegion := hmac.New(sha256.New, kDate.Sum(nil))
	_, err = kRegion.Write([]byte(region))
	if err != nil {
		return "", err
	}
	kService := hmac.New(sha256.New, kRegion.Sum(nil))
	_, err = kService.Write([]byte(service))
	if err != nil {
		return "", err
	}
	kSigning := hmac.New(sha256.New, kService.Sum(nil))
	_, err = kSigning.Write([]byte("aws4_request"))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(kSigning.Sum(nil)), nil
}

func main() {
	plugin.Register("minio-auth", CreateMinioAuth)
}
