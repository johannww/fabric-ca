//go:build pkcs11
// +build pkcs11

/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkcs11"
)

func TestCAInit(t *testing.T) {
	orgwd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	confDir, err := cdTmpTestDir("TestCAInit")
	t.Log("confDir: ", confDir)
	if err != nil {
		t.Fatal("failed to cd to tmp dir: ", err)
	}
	defer func() {
		err = os.Chdir(orgwd)
		if err != nil {
			t.Fatalf("failed to cd to %v: %s", orgwd, err)
		}
	}()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	t.Log("Working dir", wd)
	defer cleanupTmpfiles(t, wd)
	cfgFile := serverCfgFile(".")
	server := &Server{
		levels: &dbutil.Levels{
			Identity:    1,
			Affiliation: 1,
			Certificate: 1,
		},
	}
	ca, err := newCA(cfgFile, &CAConfig{}, server, false)
	if err != nil {
		t.Fatal("newCA FAILED")
	}

	// BCCSP error
	swo := &factory.SwOpts{}
	pko := &pkcs11.PKCS11Opts{}
	ca.Config.CSP = &factory.FactoryOpts{Default: "PKCS11", SW: swo, PKCS11: pko}
	ca.HomeDir = ""
	err = ca.init(false)
	t.Logf("ca.init error: %v", err)
	if err == nil {
		t.Fatalf("Server init should have failed: BCCSP err")
	}

	// delete everything and start over
	// initKeyMaterial error
	os.Chdir(orgwd)

	confDir, err = cdTmpTestDir("TestCAInit")
	if err != nil {
		t.Fatal("failed to cd to tmp dir: ", err)
	}
	wd2, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	t.Log("changed directory to ", wd2)
	defer cleanupTmpfiles(t, wd2)

	ca.Config.CSP = &factory.FactoryOpts{Default: "SW", SW: swo, PKCS11: pko}
	ca, err = newCA(cfgFile, &CAConfig{}, server, true)
	if err != nil {
		t.Fatal("newCA FAILED", err)
	}
	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	err = CopyFile("../ec256-1-key.pem", caKey)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	err = CopyFile("../ec256-2-cert.pem", caCert)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	err = ca.init(false)
	t.Log("init err: ", err)
	if err == nil {
		t.Error("Should have failed because key and cert don't match")
	}

	err = os.Remove(caKey)
	if err != nil {
		t.Fatalf("Remove failed: %s", err)
	}
	err = os.Remove(caCert)
	if err != nil {
		t.Fatalf("Remove failed: %s", err)
	}
	ca.Config.CA.Keyfile = ""
	ca.Config.CA.Certfile = ""
	ca.Config.DB.Datasource = ""
	ca, err = newCA(cfgFile, &CAConfig{}, server, false)
	if err != nil {
		t.Fatal("newCA FAILED: ", err)
	}

	err = ca.init(false)
	if err != nil {
		t.Fatal("ca init failed", err)
	}

	// initUserRegistry error
	ca.Config.LDAP.Enabled = true
	err = ca.initUserRegistry()
	t.Log("init err: ", err)
	if err == nil {
		t.Fatal("initUserRegistry should have failed")
	}

	// initEnrollmentSigner error
	ca.Config.LDAP.Enabled = false
	ca, err = newCA(cfgFile, &CAConfig{}, server, false)
	if err != nil {
		t.Fatal("newCA FAILED")
	}
	err = os.RemoveAll("./msp")
	if err != nil {
		t.Fatal("os.Remove msp failed: ", err)
	}
	err = os.Remove(caCert)
	if err != nil {
		t.Fatal("os.Remove failed: ", err)
	}
	err = CopyFile("../rsa2048-1-key.pem", caKey)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	err = CopyFile("../rsa2048-1-cert.pem", caCert)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	err = ca.init(false)
	t.Log("init err: ", err)
	if err == nil {
		t.Fatal("init should have failed")
	}

	os.Chdir(orgwd)

	confDir, err = cdTmpTestDir("TestCAInit")
	if err != nil {
		t.Fatal("failed to cd to tmp dir: ", err)
	}
	wd3, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	t.Log("changed directory to ", wd3)
	defer cleanupTmpfiles(t, wd3)

	swo = &factory.SwOpts{}
	pko = initSoftHsm(t)
	config := &CAConfig{
		CSR: api.CSRInfo{
			KeyRequest: &api.KeyRequest{
				Algo: "ed25519",
			},
		},
	}

	config.CSP = &factory.FactoryOpts{Default: "PKCS11", SW: swo, PKCS11: pko}
	ca, err = newCA(cfgFile, config, server, true)
	if err != nil {
		t.Fatalf("newCA FAILED: %s", err)
	}

	ca.HomeDir = ""
	err = ca.init(true)
	t.Logf("ca.init error: %v", err)
	if err != nil {
		t.Fatalf("Server init should not have failed: BCCSP err: %s", err)
	}

}

func initSoftHsm(t *testing.T) *pkcs11.PKCS11Opts {
	lib, pin, label := pkcs11.FindPKCS11Lib()
	if lib == "" {
		t.Fatalf("Could not find PKCS11 library. SoftHSM may not be installed")
	}

	p11 := &pkcs11.PKCS11Opts{
		Library:  lib,
		Pin:      pin,
		Label:    label,
		Hash:     "SHA2",
		Security: 256,
	}

	return p11

}
