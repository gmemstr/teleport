// Copyright 2022 Gravitational, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kinit provides utilities for interacting with a KDC (Key Distribution Center) for Kerberos5, or krb5, to allow
// teleport to connect to sqlserver using x509 certificates.
package kinit

import (
	"context"
	"fmt"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
)

/*
//#cgo CFLAGS: -g -Wno-deprecated-declarations
//#cgo LDFLAGS: -L -lgssapi_krb5 -lkrb5 -lk5crypto -libkrb5support
//#include "kinit.c"
*/
//import "C"

//func KInit(ca, userCert, userKey, cacheName string) error {
//	ret := C.kinit(C.CString(ca), C.CString(userCert), C.CString(userKey), C.CString(cacheName))
//	if ret != C.KDC_ERR_NONE {
//		return trace.Wrap(fmt.Errorf("error returned from kinit: %d", int(ret)))
//	}
//	return nil
//}

const kdcExtensionsFileText = `[ kdc_cert ]
basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, keyAgreement

#Pkinit EKU
extendedKeyUsage = 1.3.6.1.5.2.3.5

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# Copy subject details

issuerAltName=issuer:copy

# Add id-pkinit-san (pkinit subjectAlternativeName)
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

[kdc_princ_name]
realm = EXP:0, GeneralString:${ENV::REALM}
principal_name = EXP:1, SEQUENCE:kdc_principal_seq

[kdc_principal_seq]
name_type = EXP:0, INTEGER:1
name_string = EXP:1, SEQUENCE:kdc_principals

[kdc_principals]
princ1 = GeneralString:krbtgt
princ2 = GeneralString:${ENV::REALM}

[ client_cert ]

# These extensions are added when 'ca' signs a request.

basicConstraints=CA:FALSE

keyUsage = digitalSignature, keyEncipherment, keyAgreement

extendedKeyUsage =  1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer


subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name


# Copy subject details

issuerAltName=issuer:copy

[princ_name]
realm = EXP:0, GeneralString:${ENV::REALM}
principal_name = EXP:1, SEQUENCE:principal_seq

[principal_seq]
name_type = EXP:0, INTEGER:1
name_string = EXP:1, SEQUENCE:principals

[principals]
princ1 = GeneralString:${ENV::CLIENT}`

const (
	DefaultKRBConfig = "/etc/krb5.conf"
)

type KInit struct {
	CACertPath   string
	CAKeyPath    string
	UserCertPath string
	UserKeyPath  string
	UserName     string
	CacheName    string

	RealmName       string
	KDCHostName     string
	AdminServerName string

	Log logrus.FieldLogger
}

func New(ca, caKey, userCert, userKey, user, cacheName, realm, kdcHost, adminServer string) *KInit {
	return &KInit{
		CACertPath:      ca,
		CAKeyPath:       caKey,
		UserCertPath:    userCert,
		UserKeyPath:     userKey,
		UserName:        user,
		CacheName:       cacheName,
		RealmName:       realm,
		KDCHostName:     kdcHost,
		AdminServerName: adminServer,
		Log:             logrus.StandardLogger(),
	}
}

// CreateOrAppendCredentialsCache creates or appends to an existing credentials cache. There must be a valid KDC running
// at the specified certificate authority address as defined in the CA Certificate
func (k *KInit) CreateOrAppendCredentialsCache(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"kinit",
		"-X", fmt.Sprintf("X509_anchors=FILE:%s", k.CACertPath),
		"-X", fmt.Sprintf("X509_user_identity=FILE:%s,%s", k.UserCertPath, k.UserKeyPath), k.UserName,
		"-c", k.CacheName)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return trace.Wrap(err)
	}
	// todo better error handling from output/fully wrap libkrb5 for linux
	k.Log.Debug(string(data))
	return nil
}

// GenerateKDCExtensions file for openssl
func (k *KInit) GenerateKDCExtensions(path string) error {
	return os.WriteFile(path, []byte(kdcExtensionsFileText), 0644)
}

// krb5ConfigString returns a config suitable for a kdc
func (k *KInit) krb5ConfigString() string {
	return fmt.Sprintf(`[libdefaults]
 default_realm = %s
 rdns = false


[realms]
 %s = {
  kdc = %s
  admin_server = %s
  pkinit_eku_checking = kpServerAuth
  pkinit_kdc_hostname = %s
 }`, k.RealmName, k.RealmName, k.KDCHostName, k.AdminServerName, k.KDCHostName)
}

func (k *KInit) WriteKRB5Config(path string) error {
	return os.WriteFile(path, []byte(k.krb5ConfigString()), 0644)
}

// GenerateKDCCertKey generates an intermediary certificate and key pair specifically for a Kerberos Key Distribution Center
func (k *KInit) GenerateKDCCertKey(ctx context.Context, extensionsFile, country, stateProvince, locality, orgName, unit, commonName, email, outDir string) error {
	cmd := exec.CommandContext(ctx,
		"openssl", "req", "-newkey", "rsa:4096", "-sha256", "-nodes",
		"-keyout", filepath.Join(outDir, "kdckey.pem"),
		"-out", filepath.Join(outDir, "kdcreq.pem"),
		"-subj", fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, stateProvince, locality, orgName, unit, commonName, email))
	data, err := cmd.CombinedOutput()
	if err != nil {
		return trace.Wrap(err)
	}
	k.Log.Debug(string(data))

	// env REALM=ALISTANIS.GITHUB.BETA.TAILSCALE.NET openssl x509 -req -in kdc.req \\n    -CAkey cakey.pem -CA cacert.pem -out kdc.pem -days 365 \\n    -extfile extensions.kdc -extensions kdc_cert -CAcreateserial
	cmd = exec.CommandContext(ctx,
		"openssl", "x509", "-req", "-in", filepath.Join(outDir, "kdcreq.pem"),
		"-CAkey", k.CAKeyPath,
		"-CA", k.CACertPath,
		"-out", filepath.Join(outDir, "kdc.pem"),
		"-days", "3650",
		"-extfile", extensionsFile,
		"-extensions", "kdc_cert",
		"-CACreateserial",
	)

	cmd.Env = append(cmd.Env, []string{fmt.Sprintf("REALM=%s", k.RealmName)}...)
	data, err = cmd.CombinedOutput()
	if err != nil {
		return trace.Wrap(err)
	}
	k.Log.Debug(string(data))

	return nil
}

// GenerateClientCertKey generates a client certificate and key pair for use with Kerberos x509 authentication
func (k *KInit) GenerateClientCertKey(ctx context.Context, extensionsFile, country, stateProvince, locality, orgName, unit, commonName, email, outDir string) error {
	keyName := fmt.Sprintf("%s-key.pem", commonName)
	reqName := fmt.Sprintf("%s-req.pem", commonName)
	certName := fmt.Sprintf("%s-cert.pem", commonName)

	keyPath := filepath.Join(outDir, keyName)
	reqPath := filepath.Join(outDir, reqName)
	certPath := filepath.Join(outDir, certName)

	cmd := exec.CommandContext(ctx,
		"openssl", "req", "-newkey", "rsa:4096", "-sha256", "-nodes",
		"-keyout", keyPath,
		"-out", reqPath,
		"-subj", fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s", country, stateProvince, locality, orgName, unit, commonName, email))
	data, err := cmd.CombinedOutput()
	if err != nil {
		return trace.Wrap(err)
	}
	k.Log.Debug(string(data))

	// env REALM=ALISTANIS.GITHUB.BETA.TAILSCALE.NET; export REALM; CLIENT=chris; export CLIENT; openssl x509 -CAkey cakey.pem -CA cacert.pem -req -in client.req -extensions client_cert -extfile extensions.kdc  -out client.pem\n
	cmd = exec.CommandContext(ctx,
		"openssl", "x509", "-req", "-in", reqPath,
		"-CAkey", k.CAKeyPath,
		"-CA", k.CACertPath,
		"-out", certPath,
		"-days", "3650",
		"-extfile", extensionsFile,
		"-extensions", "client_cert",
		"-CACreateserial",
	)

	cmd.Env = append(cmd.Env, []string{fmt.Sprintf("REALM=%s", k.RealmName), fmt.Sprintf("CLIENT=%s", commonName)}...)
	data, err = cmd.CombinedOutput()
	if err != nil {
		return trace.Wrap(err)
	}
	k.Log.Debug(string(data))

	return nil
}
