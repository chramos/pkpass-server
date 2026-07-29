package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/alvinbaena/passkit"
	"golang.org/x/crypto/pkcs12"
)

const (
	certsDir   = "certs"
	passDir    = "pass.pass"
	addr       = ":8080"
	p12Pass    = "Abcd1234!!"
	apnsTopic  = "pass.com.vthru.mobile.stage"
	devicesFile = "data/devices.json"
)

var (
	signingInfo *passkit.SigningInformation
	apnsClient  *http.Client

	mu          sync.RWMutex
	devices     = map[string]string{} // deviceId -> pushToken
	lastUpdated = "1"
)

func main() {
	var err error
	signingInfo, err = passkit.LoadSigningInformationFromFiles(
		certsDir+"/passcertificate.p12",
		p12Pass,
		certsDir+"/AppleWWDR.cer",
	)
	if err != nil {
		log.Fatal("failed to load signing info: ", err)
	}

	apnsClient, err = newAPNsClient(certsDir+"/passcertificate.p12", p12Pass)
	if err != nil {
		log.Fatal("failed to create APNs client: ", err)
	}

	loadDevices()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /pass.pkpass", handleDownloadPass)

	mux.HandleFunc("POST /v1/devices/{deviceId}/registrations/{passTypeId}/{serial}", handleRegister)
	mux.HandleFunc("DELETE /v1/devices/{deviceId}/registrations/{passTypeId}/{serial}", handleUnregister)
	mux.HandleFunc("GET /v1/devices/{deviceId}/registrations/{passTypeId}", handleSerials)
	mux.HandleFunc("GET /v1/passes/{passTypeId}/{serial}", handleLatestPass)
	mux.HandleFunc("POST /v1/log", handleLog)

	mux.HandleFunc("GET /admin/devices", handleListDevices)
	mux.HandleFunc("POST /admin/push", handlePushUpdate)

	log.Printf("server running on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// APNs client using the same .p12 cert
func newAPNsClient(p12Path, password string) (*http.Client, error) {
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, err
	}
	privateKey, cert, err := pkcs12.Decode(p12Data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode p12: %w", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		},
		Timeout: 10 * time.Second,
	}, nil
}

func loadDevices() {
	os.MkdirAll("data", 0755)
	data, err := os.ReadFile(devicesFile)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	json.Unmarshal(data, &devices)
	log.Printf("loaded %d devices from %s", len(devices), devicesFile)
}

func saveDevices() {
	data, _ := json.MarshalIndent(devices, "", "  ")
	os.WriteFile(devicesFile, data, 0644)
}

func sendPushToDevice(pushToken string) error {
	// ponytail: using production APNs; switch to api.sandbox.push.apple.com for dev certs
	url := fmt.Sprintf("https://api.push.apple.com/3/device/%s", pushToken)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("apns-topic", apnsTopic)
	req.Header.Set("apns-push-type", "background")
	req.Header.Set("apns-priority", "5")

	resp, err := apnsClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APNs returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func buildPass() ([]byte, error) {
	c := passkit.NewGenericPass()

	c.AddHeaderField(passkit.Field{
		Key: "phone", Label: "PHONE", Value: "+965-97927277",
	})
	c.AddPrimaryFields(passkit.Field{
		Key: "name", Label: "NAME", Value: "Abdullah\nAlshalabi",
	})
	c.AddSecondaryFields(passkit.Field{
		Key: "clubs", Label: "CLUBS", Value: "Universities Club • PRIME Club • Elite Club • Apple Club",
	})
	c.AddBackFields(passkit.Field{
		Key: "full_clubs", Label: "MY CLUBS", Value: "Universities Club • PRIME Club • Elite Club • Apple Club • Google Club",
	})

	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "67G5HMJZ6R",
		PassTypeIdentifier:  apnsTopic,
		OrganizationName:    "V-Thru",
		SerialNumber:        "4",
		Description:         "V-Thru",
		AuthenticationToken: "vthru-passkit-token-2026",
		WebServiceURL:       "https://passkit.hramos.dev",
		Generic:             c,
		Locations: []passkit.Location{
			{
				Latitude:     29.3337625,
				Longitude:    47.6475469,
				RelevantText: "Your V-Thru rewards are waiting at Elevation Burger!",
			},
			{
				Latitude:     29.3276875,
				Longitude:    47.6545625,
				RelevantText: "Hungry? Skip the line at Burger King with V-Thru!",
			},
			{
				Latitude:     29.3276875,
				Longitude:    47.6546875,
				RelevantText: "Pizza craving? Order ahead at Pizza Hut with V-Thru!",
			},
			{
				Latitude:     29.3132463,
				Longitude:    47.6595451,
				RelevantText: "Fresh juice is just a tap away at Aseer Time!",
			},
			{
				Latitude:     29.3120875,
				Longitude:    47.6600469,
				RelevantText: "Earn points on your next Caribou Coffee order!",
			},
			{
				Latitude:     29.3121375,
				Longitude:    47.6601406,
				RelevantText: "PICK up something special — order now with V-Thru!",
			},
			{
				Latitude:     29.312142,
				Longitude:    47.660361,
				RelevantText: "Coffee Bean & Tea Leaf is nearby — treat yourself!",
			},
			{
				Latitude:     29.3182195,
				Longitude:    47.6591566,
				RelevantText: "SEALED is right here — grab your favorite drink!",
			},
			{Latitude: 29.3181938, Longitude: 47.659272, RelevantText: "Chocolate lovers — CocoaVia is steps away!"},
			{
				Latitude:     29.3182875,
				Longitude:    47.6596094,
				RelevantText: "Fresh pastries at Mama's Bakery — order via V-Thru!",
			},
		},
		Barcodes: []passkit.Barcode{
			{Format: passkit.BarcodeFormatQR, Message: `{"id": 4}`, MessageEncoding: "utf-8"},
		},
	}

	template := passkit.NewFolderPassTemplate(passDir)
	signer := passkit.NewMemoryBasedSigner()
	return signer.CreateSignedAndZippedPassArchive(&pass, template, signingInfo)
}

func handleDownloadPass(w http.ResponseWriter, r *http.Request) {
	z, err := buildPass()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apple.pkpass")
	w.Header().Set("Content-Disposition", "attachment; filename=pass.pkpass")
	w.Write(z)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	deviceId := r.PathValue("deviceId")
	serial := r.PathValue("serial")

	var body struct {
		PushToken string `json:"pushToken"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	log.Printf("register: device=%s serial=%s pushToken=%s", deviceId, serial, body.PushToken)

	mu.Lock()
	_, exists := devices[deviceId]
	devices[deviceId] = body.PushToken
	saveDevices()
	mu.Unlock()

	if exists {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func handleUnregister(w http.ResponseWriter, r *http.Request) {
	deviceId := r.PathValue("deviceId")
	log.Printf("unregister: device=%s", deviceId)

	mu.Lock()
	delete(devices, deviceId)
	saveDevices()
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func handleSerials(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("passesUpdatedSince")
	if tag == lastUpdated {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"lastUpdated":"%s","serialNumbers":["1234"]}`, lastUpdated)
}

func handleLatestPass(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	log.Printf("latest pass requested: serial=%s", serial)

	z, err := buildPass()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apple.pkpass")
	w.Write(z)
}

func handleLog(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("wallet log: %s", string(body))
	w.WriteHeader(http.StatusOK)
}

func handleListDevices(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	if len(devices) == 0 {
		fmt.Fprintln(w, "no devices registered")
		return
	}
	for id, token := range devices {
		fmt.Fprintf(w, "device=%s pushToken=%s\n", id, token)
	}
}

// POST /admin/push — bump lastUpdated and notify all devices
func handlePushUpdate(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	n, _ := strconv.Atoi(lastUpdated)
	lastUpdated = strconv.Itoa(n + 1)
	tokensCopy := make(map[string]string, len(devices))
	for k, v := range devices {
		tokensCopy[k] = v
	}
	mu.Unlock()

	if len(tokensCopy) == 0 {
		fmt.Fprintln(w, "no devices to notify")
		return
	}

	var errors []string
	for deviceId, pushToken := range tokensCopy {
		if err := sendPushToDevice(pushToken); err != nil {
			log.Printf("push failed for device=%s: %v", deviceId, err)
			errors = append(errors, fmt.Sprintf("%s: %v", deviceId, err))
		} else {
			log.Printf("push sent to device=%s", deviceId)
		}
	}

	if len(errors) > 0 {
		fmt.Fprintf(w, "pushed with %d errors:\n%s\n", len(errors), errors)
	} else {
		fmt.Fprintf(w, "pushed to %d devices\n", len(tokensCopy))
	}
}
