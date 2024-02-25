package encoder

import (
	"testing"
)

func TestTypeDetectWithPEMPKCS8(t *testing.T) {
	data := []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALZJ8dcxDnC91DwZ
frPZBkz0q7HUm/buVoc8ZQotAnqkugbGvcYFKS7CZqwKREXVf2nY80DJBEGkldKq
kBr6K6eyqPbR7R16jkC3Lc78wYeMJLwQ245f2WNazXYbOODmnvcTZAbHxiI6giKW
GrwgOvFP39AqWVfDwM7L5q8ARlTnAgMBAAECgYEAkR7BJ33obxzQ75+kXO1ztKQ8
Y/BM0gLgY/1Suw0mIhkt9+MUhabqKE2fi2sI+0eCjfOnhHYDq3apx/L9klyDjz96
ld8cfnglNhzBoAUMoE4L25/UHPBL+CPYZ2fgNeRFx7Dqf+bOdTgVnf8LK2TDHjPu
+h8AIbNrek7UTUgFXWECQQDLbcVIb8wL1cH5i/ANvu/Kn4qyPTOaS77kRiS/nUjD
zC8SJui/Rmu/yKvgyJf1oXQiimzzY0cabAml8Sx1dWUZAkEA5WWeohl6vlFsrzVA
0/YiD8BR1+mW6l5Ph5ddwrBSNrn0KU46TIhoQ7yBZElds8SBfWKB+EC7Lgpn+CXA
bGbJ/wJBAL/cLb7dwgI/fozPUH6GYD4oLnVgh3S0j7tX9HzL6L7RqmtiSw1ra2Ab
8Q814SwHNDMHfy4lqf/feVIKnjXBnLECQDDrcuDuvhZIFv1mReTt4GWrhcidr+lb
I2qvBPe30lCJZ2BHpncbv+ByGsXgP3NOvK6Yi079vu0amwF4S4jSgtECQQCZaij4
PAO/StMh/ywsIP/Yo6l1rlPtfoLRIAtx4qQLnxQFFGV6PjUiLqBN0e0kHZvB1NXt
d2FTNrzVEw/RgXfv
-----END PRIVATE KEY-----`)

	types := TypeDetect(data)
	if types[0] != KeyFileFormatPEM {
		t.Errorf("Expected PEM, got %s", types[0].String())
	}

	if types[1] != KeyFileFormatPKCS8PrivateKey {
		t.Errorf("Expected PKCS8PrivateKey, got %s", types[1].String())
	}
}
