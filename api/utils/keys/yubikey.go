//go:build !linux || libpcsclite
// +build !linux libpcsclite

/*
Copyright 2022 Gravitational, Inc.
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

package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api"
	attestation "github.com/gravitational/teleport/api/gen/proto/go/attestation/v1"
	"github.com/gravitational/teleport/api/utils/retryutils"
)

const (
	// PIVCardTypeYubiKey is the PIV card type assigned to yubiKeys.
	PIVCardTypeYubiKey = "yubikey"
)

var (
	// We use slot 9a for Teleport Clients which require `private_key_policy: hardware_key`.
	pivSlotNoTouch = piv.SlotAuthentication
	// We use slot 9c for Teleport Clients which require `private_key_policy: hardware_key_touch`.
	// Private keys generated on this slot will use TouchPolicy=Cached.
	pivSlotWithTouch = piv.SlotSignature
)

// getOrGenerateYubiKeyPrivateKey connects to a connected yubiKey and gets a private key
// matching the given touch requirement. This private key will either be newly generated
// or previously generated by a Teleport client and reused.
func getOrGenerateYubiKeyPrivateKey(ctx context.Context, touchRequired bool) (*PrivateKey, error) {
	// Use the first yubiKey we find.
	y, err := findYubiKey(ctx, 0)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get the correct PIV slot and Touch policy for the given touch requirement.
	pivSlot := pivSlotNoTouch
	touchPolicy := piv.TouchPolicyNever
	if touchRequired {
		pivSlot = pivSlotWithTouch
		touchPolicy = piv.TouchPolicyCached
	}

	// First, check if there is already a private key set up by a Teleport Client.
	priv, err := y.getPrivateKey(ctx, pivSlot)
	if err != nil {
		// Generate a new private key on the PIV slot.
		if priv, err = y.generatePrivateKey(ctx, pivSlot, touchPolicy); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	keyPEM, err := priv.keyPEM()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return NewPrivateKey(priv, keyPEM)
}

// YubiKeyPrivateKey is a YubiKey PIV private key. Cryptographical operations open
// a new temporary connection to the PIV card to perform the operation.
type YubiKeyPrivateKey struct {
	// yubiKey is a specific yubiKey PIV module.
	*yubiKey
	pivSlot piv.Slot
	pub     crypto.PublicKey
}

// yubiKeyPrivateKeyData is marshalable data used to retrieve a specific yubiKey PIV private key.
type yubiKeyPrivateKeyData struct {
	SerialNumber uint32 `json:"serial_number"`
	SlotKey      uint32 `json:"slot_key"`
}

func newYubiKeyPrivateKey(ctx context.Context, y *yubiKey, slot piv.Slot, pub crypto.PublicKey) (*YubiKeyPrivateKey, error) {
	return &YubiKeyPrivateKey{
		yubiKey: y,
		pivSlot: slot,
		pub:     pub,
	}, nil
}

func parseYubiKeyPrivateKeyData(keyDataBytes []byte) (*YubiKeyPrivateKey, error) {
	// TODO (Joerger): rather than requiring a context be passed here, we should
	// pre-load the yubikey PIV connection to avoid retry/context logic occurring
	// at spontaneous points in the code (anywhere a private key is used).
	ctx := context.TODO()

	var keyData yubiKeyPrivateKeyData
	if err := json.Unmarshal(keyDataBytes, &keyData); err != nil {
		return nil, trace.Wrap(err)
	}

	pivSlot, err := parsePIVSlot(keyData.SlotKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	y, err := findYubiKey(ctx, keyData.SerialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	priv, err := y.getPrivateKey(ctx, pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return priv, nil
}

// Public returns the public key corresponding to this private key.
func (y *YubiKeyPrivateKey) Public() crypto.PublicKey {
	return y.pub
}

// Sign implements crypto.Signer.
func (y *YubiKeyPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	privateKey, err := yk.PrivateKey(y.pivSlot, y.pub, piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if y.pivSlot == pivSlotWithTouch {
		cancelTouchPrompt := delayedTouchPrompt(signTouchPromptDelay)
		defer cancelTouchPrompt()
	}

	signature, err := privateKey.(crypto.Signer).Sign(rand, digest, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return signature, nil
}

func (y *YubiKeyPrivateKey) keyPEM() ([]byte, error) {
	keyDataBytes, err := json.Marshal(yubiKeyPrivateKeyData{
		SerialNumber: y.serialNumber,
		SlotKey:      y.pivSlot.Key,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    pivYubiKeyPrivateKeyType,
		Headers: nil,
		Bytes:   keyDataBytes,
	}), nil
}

// GetAttestationStatement returns an AttestationStatement for this YubiKeyPrivateKey.
func (y *YubiKeyPrivateKey) GetAttestationStatement() (*attestation.AttestationStatement, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	slotCert, err := yk.Attest(y.pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &attestation.AttestationStatement{
		AttestationStatement: &attestation.AttestationStatement_YubikeyAttestationStatement{
			YubikeyAttestationStatement: &attestation.YubiKeyAttestationStatement{
				SlotCert:        slotCert.Raw,
				AttestationCert: attCert.Raw,
			},
		},
	}, nil
}

// GetPrivateKeyPolicy returns the PrivateKeyPolicy supported by this YubiKeyPrivateKey.
func (k *YubiKeyPrivateKey) GetPrivateKeyPolicy() PrivateKeyPolicy {
	switch k.pivSlot {
	case pivSlotNoTouch:
		return PrivateKeyPolicyHardwareKey
	case pivSlotWithTouch:
		return PrivateKeyPolicyHardwareKeyTouch
	default:
		return PrivateKeyPolicyNone
	}
}

// yubiKey is a specific yubiKey PIV card.
type yubiKey struct {
	// card is a reader name used to find and connect to this yubiKey.
	// This value may change between OS's, or with other system changes.
	card string
	// serialNumber is the yubiKey's 8 digit serial number.
	serialNumber uint32
}

func newYubiKey(ctx context.Context, card string) (*yubiKey, error) {
	y := &yubiKey{card: card}

	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	y.serialNumber, err = yk.Serial()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return y, nil
}

// generatePrivateKey generates a new private key from the given PIV slot with the given PIV policies.
func (y *yubiKey) generatePrivateKey(ctx context.Context, slot piv.Slot, touchPolicy piv.TouchPolicy) (*YubiKeyPrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	opts := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: touchPolicy,
	}

	if slot == pivSlotWithTouch {
		cancelTouchPrompt := delayedTouchPrompt(generateKeyTouchPromptDelay)
		defer cancelTouchPrompt()
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, slot, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a self signed certificate and store it in the PIV slot so that other
	// Teleport Clients know to reuse the stored key instead of genearting a new one.
	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cert, err := selfSignedTeleportClientCertificate(priv, pub)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Store a self-signed certificate to mark this slot as used by tsh.
	if err = yk.SetCertificate(piv.DefaultManagementKey, slot, cert); err != nil {
		return nil, trace.Wrap(err)
	}

	return newYubiKeyPrivateKey(ctx, y, slot, pub)
}

// getPrivateKey gets an existing private key from the given PIV slot.
func (y *yubiKey) getPrivateKey(ctx context.Context, slot piv.Slot) (*YubiKeyPrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	// Check the slot's certificate to see if it contains a self signed Teleport Client cert.
	cert, err := yk.Certificate(slot)
	if err != nil || cert == nil {
		return nil, trace.NotFound("YubiKey certificate slot is empty, expected a Teleport Client cert")
	} else if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != certOrgName {
		return nil, trace.NotFound("YubiKey certificate slot contained unknown certificate:\n%+v", cert)
	}

	return newYubiKeyPrivateKey(ctx, y, slot, cert.PublicKey)
}

// open a connection to YubiKey PIV module. The returned connection should be closed once
// it's been used. The YubiKey PIV module itself takes some additional time to handle closed
// connections, so we use a retry loop to give the PIV module time to close prior connections.
func (y *yubiKey) open() (yk *piv.YubiKey, err error) {
	linearRetry, err := retryutils.NewLinear(retryutils.LinearConfig{
		// If a PIV connection has just been closed, it take ~5 ms to become
		// available to new connections. For this reason, we initially wait a
		// short 10ms before stepping up to a longer 50ms retry.
		First: time.Millisecond * 10,
		Step:  time.Millisecond * 10,
		// Since PIV modules only allow a single connection, it is a bottleneck
		// resource. To maximise usage, we use a short 50ms retry to catch the
		// connection opening up as soon as possible.
		Max: time.Millisecond * 50,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Backoff and retry for up to 1 second.
	retryCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = linearRetry.For(retryCtx, func() error {
		yk, err = piv.Open(y.card)
		if err != nil && !isRetryError(err) {
			return retryutils.PermanentRetryError(err)
		}
		return trace.Wrap(err)
	})
	if trace.IsLimitExceeded(err) {
		// Using PIV syncronously causes issues since only one connection is allowed at a time.
		// This shouldn't be an issue for `tsh` which primarily runs consecutively, but Teleport
		// Connect works through callbacks, etc. and may try to open multiple connections at a time.
		// If this error is being emitted more than rarely, the 1 second timeout may need to be increased.
		//
		// It's also possible that the user is running another PIV program, which may hold the PIV
		// connection indefinitely (yubikey-agent). In this case, user action is necessary, so we
		// alert them with this issue.
		return nil, trace.LimitExceeded("could not connect to YubiKey as another application is using it. Please try again once the program that uses the YubiKey, such as yubikey-agent is closed")
	} else if err != nil {
		return nil, trace.Wrap(err)
	}
	return yk, nil
}

func isRetryError(err error) bool {
	const retryError = "connecting to smart card: the smart card cannot be accessed because of other connections outstanding"
	return strings.Contains(err.Error(), retryError)
}

// findYubiKey finds a yubiKey PIV card by serial number. If no serial
// number is provided, the first yubiKey found will be returned.
func findYubiKey(ctx context.Context, serialNumber uint32) (*yubiKey, error) {
	yubiKeyCards, err := findYubiKeyCards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(yubiKeyCards) == 0 {
		return nil, trace.NotFound("no yubiKey devices found")
	}

	for _, card := range yubiKeyCards {
		y, err := newYubiKey(ctx, card)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if serialNumber == 0 || y.serialNumber == serialNumber {
			return y, nil
		}
	}

	return nil, trace.NotFound("no yubiKey device found with serial number %q", serialNumber)
}

// findYubiKeyCards returns a list of connected yubiKey PIV card names.
func findYubiKeyCards() ([]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var yubiKeyCards []string
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), PIVCardTypeYubiKey) {
			yubiKeyCards = append(yubiKeyCards, card)
		}
	}

	return yubiKeyCards, nil
}

func parsePIVSlot(slotKey uint32) (piv.Slot, error) {
	switch slotKey {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, nil
	case piv.SlotSignature.Key:
		return piv.SlotSignature, nil
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, nil
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, nil
	default:
		retiredSlot, ok := piv.RetiredKeyManagementSlot(slotKey)
		if !ok {
			return piv.Slot{}, trace.BadParameter("slot %X does not exist", slotKey)
		}
		return retiredSlot, nil
	}
}

// certOrgName is used to identify Teleport Client self-signed certificates stored in yubiKey PIV slots.
const certOrgName = "teleport"

func selfSignedTeleportClientCertificate(priv crypto.PrivateKey, pub crypto.PublicKey) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit) // see crypto/tls/generate_cert.go
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		PublicKey:    pub,
		Subject: pkix.Name{
			Organization:       []string{certOrgName},
			OrganizationalUnit: []string{api.Version},
		},
	}
	if cert.Raw, err = x509.CreateCertificate(rand.Reader, cert, cert, pub, priv); err != nil {
		return nil, trace.Wrap(err)
	}
	return cert, nil
}

// YubiKeys require touch when generating a private key that requires touch, or using
// a private key (Sign) with touch required. Unfortunately, there is no good way to
// check whether touch is cached by the PIV module at a given time. In order to require
// touch only when needed, we prompt for touch after a short delay when we expect the
// request would succeed if touch were not required.
//
// There are some X factors which determine how long a request may take, such as the
// YubiKey model and firmware version, so the delays below may need to be adjusted to
// suit more models. The durations mentioned below were retrieved from testing with a
// YubiKey 5 nano (5.2.7) and a YubiKey NFC (5.4.3).
const (
	// piv.ECDSAPrivateKey.Sign consistently takes ~70 milliseconds. We don't want to delay signatures
	// much since they happen frequently, so we use a liberal delay of 100ms.
	signTouchPromptDelay = time.Millisecond * 100
	// piv.YubiKey.GenerateKey can take between 80 and 320ms. We use a slightly more
	// conservative delay of 500ms since this only occurs once on login.
	generateKeyTouchPromptDelay = time.Millisecond * 500
)

// delayedTouchPrompt prompts the user for touch after the given delay.
// The returned cancel function can be used to cancel the prompt if the
// calling function succeeds without touch, meaning touch was cached.
func delayedTouchPrompt(delay time.Duration) (cancel func()) {
	touchCtx, cancel := context.WithTimeout(context.Background(), delay)
	go func() {
		<-touchCtx.Done()
		if touchCtx.Err() == context.DeadlineExceeded {
			fmt.Fprintln(os.Stderr, "Tap your YubiKey")
		}
	}()

	return cancel
}
