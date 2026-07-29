package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alvinbaena/passkit"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/http2"
)

const (
	certsDir  = "certs"
	passDir   = "pass.pass"
	addr      = ":8080"
	p12Pass   = "Abcd1234!!"
	apnsTopic = "pass.com.vthru.mobile.stage"
)

var (
	db          *sql.DB
	signingInfo *passkit.SigningInformation
	apnsClient  *http.Client
)

func main() {
	var err error

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://pkpass:pkpass@localhost:5432/pkpass?sslmode=disable"
	}
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("failed to connect to db: ", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal("failed to ping db: ", err)
	}
	initDB()

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

	mux := http.NewServeMux()

	mux.HandleFunc("GET /pass/{serial}.pkpass", handleDownloadPass)

	mux.HandleFunc("POST /v1/devices/{deviceId}/registrations/{passTypeId}/{serial}", handleRegister)
	mux.HandleFunc("DELETE /v1/devices/{deviceId}/registrations/{passTypeId}/{serial}", handleUnregister)
	mux.HandleFunc("GET /v1/devices/{deviceId}/registrations/{passTypeId}", handleSerials)
	mux.HandleFunc("GET /v1/passes/{passTypeId}/{serial}", handleLatestPass)
	mux.HandleFunc("POST /v1/log", handleLog)

	mux.HandleFunc("GET /admin/passes", handleListPasses)
	mux.HandleFunc("POST /admin/passes", handleCreatePass)
	mux.HandleFunc("PUT /admin/passes/{serial}", handleUpdatePass)
	mux.HandleFunc("GET /admin/devices", handleListDevices)
	mux.HandleFunc("POST /admin/push/{serial}", handlePushBySerial)
	mux.HandleFunc("POST /admin/push", handlePushAll)

	log.Printf("server running on %s", addr)
	log.Fatal(http.ListenAndServe(addr, corsMiddleware(mux)))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func initDB() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS passes (
			serial TEXT PRIMARY KEY,
			customer_id TEXT NOT NULL,
			phone TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			clubs TEXT NOT NULL DEFAULT '',
			full_clubs TEXT NOT NULL DEFAULT '',
			photo_url TEXT NOT NULL DEFAULT '',
			locations JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS devices (
			device_id TEXT NOT NULL,
			serial TEXT NOT NULL REFERENCES passes(serial) ON DELETE CASCADE,
			push_token TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (device_id, serial)
		);
	`)
	if err != nil {
		log.Fatal("failed to init db: ", err)
	}
}

type PassData struct {
	Serial     string     `json:"serial"`
	CustomerID string     `json:"customer_id"`
	Phone      string     `json:"phone"`
	Name       string     `json:"name"`
	Clubs      string     `json:"clubs"`
	FullClubs  string     `json:"full_clubs"`
	PhotoURL   string     `json:"photo_url"`
	Locations  []Location `json:"locations"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type Location struct {
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	RelevantText string  `json:"relevant_text"`
}

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
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

func sendPushToDevice(pushToken string) error {
	url := fmt.Sprintf("https://api.push.apple.com/3/device/%s", pushToken)
	req, err := http.NewRequest("POST", url, strings.NewReader("{}"))
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

func buildPassFromData(p PassData) ([]byte, error) {
	c := passkit.NewGenericPass()

	c.AddHeaderField(passkit.Field{
		Key: "phone", Label: "PHONE", Value: p.Phone,
	})
	c.AddPrimaryFields(passkit.Field{
		Key: "name", Label: "NAME", Value: p.Name,
	})
	c.AddSecondaryFields(passkit.Field{
		Key: "clubs", Label: "CLUBS", Value: p.Clubs,
	})
	c.AddBackFields(passkit.Field{
		Key: "full_clubs", Label: "MY CLUBS", Value: p.FullClubs,
	})

	var locations []passkit.Location
	for _, l := range p.Locations {
		locations = append(locations, passkit.Location{
			Latitude:     l.Latitude,
			Longitude:    l.Longitude,
			RelevantText: l.RelevantText,
		})
	}

	pass := passkit.Pass{
		FormatVersion:       1,
		TeamIdentifier:      "67G5HMJZ6R",
		PassTypeIdentifier:  apnsTopic,
		OrganizationName:    "V-Thru",
		SerialNumber:        p.Serial,
		Description:         "V-Thru",
		AuthenticationToken: "vthru-passkit-token-2026",
		WebServiceURL:       "https://passkit.hramos.dev",
		Generic:             c,
		Locations:           locations,
		Barcodes: []passkit.Barcode{
			{Format: passkit.BarcodeFormatQR, Message: fmt.Sprintf(`{"id":%s}`, p.CustomerID), MessageEncoding: "utf-8"},
		},
	}

	template := passkit.NewFolderPassTemplate(passDir)

	if p.PhotoURL != "" {
		photoData, err := downloadPhoto(p.PhotoURL)
		if err != nil {
			log.Printf("failed to download photo: %v", err)
		} else {
			tmpl := passkit.NewInMemoryPassTemplate()
			tmpl.AddAllFiles(passDir)
			tmpl.AddFileBytes("thumbnail.png", photoData)
			tmpl.AddFileBytes("thumbnail@2x.png", photoData)
			return passkit.NewMemoryBasedSigner().CreateSignedAndZippedPassArchive(&pass, tmpl, signingInfo)
		}
	}

	signer := passkit.NewMemoryBasedSigner()
	return signer.CreateSignedAndZippedPassArchive(&pass, template, signingInfo)
}

func downloadPhoto(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("photo download returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func getPass(serial string) (PassData, error) {
	var p PassData
	var locJSON []byte
	err := db.QueryRow(
		`SELECT serial, customer_id, phone, name, clubs, full_clubs, photo_url, locations, created_at, updated_at FROM passes WHERE serial = $1`,
		serial,
	).Scan(&p.Serial, &p.CustomerID, &p.Phone, &p.Name, &p.Clubs, &p.FullClubs, &p.PhotoURL, &locJSON, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return p, err
	}
	json.Unmarshal(locJSON, &p.Locations)
	return p, nil
}

// GET /pass/{serial}.pkpass
func handleDownloadPass(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	p, err := getPass(serial)
	if err != nil {
		http.Error(w, "pass not found", 404)
		return
	}
	z, err := buildPassFromData(p)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apple.pkpass")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pkpass", serial))
	w.Write(z)
}

// POST /v1/devices/{deviceId}/registrations/{passTypeId}/{serial}
func handleRegister(w http.ResponseWriter, r *http.Request) {
	deviceId := r.PathValue("deviceId")
	serial := r.PathValue("serial")

	var body struct {
		PushToken string `json:"pushToken"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	log.Printf("register: device=%s serial=%s pushToken=%s", deviceId, serial, body.PushToken)

	_, err := db.Exec(
		`INSERT INTO devices (device_id, serial, push_token) VALUES ($1, $2, $3)
		 ON CONFLICT (device_id, serial) DO UPDATE SET push_token = $3`,
		deviceId, serial, body.PushToken,
	)
	if err != nil {
		log.Printf("register error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// DELETE /v1/devices/{deviceId}/registrations/{passTypeId}/{serial}
func handleUnregister(w http.ResponseWriter, r *http.Request) {
	deviceId := r.PathValue("deviceId")
	serial := r.PathValue("serial")
	log.Printf("unregister: device=%s serial=%s", deviceId, serial)

	db.Exec(`DELETE FROM devices WHERE device_id = $1 AND serial = $2`, deviceId, serial)
	w.WriteHeader(http.StatusOK)
}

// GET /v1/devices/{deviceId}/registrations/{passTypeId}
func handleSerials(w http.ResponseWriter, r *http.Request) {
	deviceId := r.PathValue("deviceId")
	rows, err := db.Query(`SELECT serial FROM devices WHERE device_id = $1`, deviceId)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer rows.Close()

	var serials []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		serials = append(serials, s)
	}
	if len(serials) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	serialsJSON, _ := json.Marshal(serials)
	fmt.Fprintf(w, `{"lastUpdated":"%d","serialNumbers":%s}`, time.Now().Unix(), serialsJSON)
}

// GET /v1/passes/{passTypeId}/{serial}
func handleLatestPass(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	log.Printf("latest pass requested: serial=%s", serial)

	p, err := getPass(serial)
	if err != nil {
		http.Error(w, "pass not found", 404)
		return
	}
	z, err := buildPassFromData(p)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.apple.pkpass")
	w.Write(z)
}

// POST /v1/log
func handleLog(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("wallet log: %s", string(body))
	w.WriteHeader(http.StatusOK)
}

// GET /admin/passes
func handleListPasses(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT serial, customer_id, phone, name, clubs, full_clubs, photo_url, locations, created_at, updated_at FROM passes ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var passes []PassData
	for rows.Next() {
		var p PassData
		var locJSON []byte
		rows.Scan(&p.Serial, &p.CustomerID, &p.Phone, &p.Name, &p.Clubs, &p.FullClubs, &p.PhotoURL, &locJSON, &p.CreatedAt, &p.UpdatedAt)
		json.Unmarshal(locJSON, &p.Locations)
		passes = append(passes, p)
	}
	if passes == nil {
		passes = []PassData{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(passes)
}

// POST /admin/passes
func handleCreatePass(w http.ResponseWriter, r *http.Request) {
	var p PassData
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if p.Serial == "" || p.CustomerID == "" {
		http.Error(w, "serial and customer_id are required", 400)
		return
	}

	locJSON, _ := json.Marshal(p.Locations)
	_, err := db.Exec(
		`INSERT INTO passes (serial, customer_id, phone, name, clubs, full_clubs, photo_url, locations) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		p.Serial, p.CustomerID, p.Phone, p.Name, p.Clubs, p.FullClubs, p.PhotoURL, locJSON,
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	downloadURL := fmt.Sprintf("https://passkit.hramos.dev/pass/%s.pkpass", p.Serial)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"serial":       p.Serial,
		"download_url": downloadURL,
	})
}

// PUT /admin/passes/{serial}
func handleUpdatePass(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")

	var p PassData
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	locJSON, _ := json.Marshal(p.Locations)
	_, err := db.Exec(
		`UPDATE passes SET phone=$1, name=$2, clubs=$3, full_clubs=$4, photo_url=$5, locations=$6, updated_at=NOW() WHERE serial=$7`,
		p.Phone, p.Name, p.Clubs, p.FullClubs, p.PhotoURL, locJSON, serial,
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// GET /admin/devices
func handleListDevices(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT device_id, serial, push_token FROM devices`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	type Device struct {
		DeviceID  string `json:"device_id"`
		Serial    string `json:"serial"`
		PushToken string `json:"push_token"`
	}
	var devices []Device
	for rows.Next() {
		var d Device
		rows.Scan(&d.DeviceID, &d.Serial, &d.PushToken)
		devices = append(devices, d)
	}
	if devices == nil {
		devices = []Device{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// POST /admin/push/{serial} — push to devices with this specific serial
func handlePushBySerial(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")

	rows, err := db.Query(`SELECT device_id, push_token FROM devices WHERE serial = $1`, serial)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var pushed, failed int
	for rows.Next() {
		var deviceId, pushToken string
		rows.Scan(&deviceId, &pushToken)
		if err := sendPushToDevice(pushToken); err != nil {
			log.Printf("push failed for device=%s: %v", deviceId, err)
			failed++
		} else {
			log.Printf("push sent to device=%s serial=%s", deviceId, serial)
			pushed++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"pushed": pushed, "failed": failed})
}

// POST /admin/push — push to all devices
func handlePushAll(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT device_id, push_token FROM devices`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var pushed, failed int
	for rows.Next() {
		var deviceId, pushToken string
		rows.Scan(&deviceId, &pushToken)
		if err := sendPushToDevice(pushToken); err != nil {
			log.Printf("push failed for device=%s: %v", deviceId, err)
			failed++
		} else {
			log.Printf("push sent to device=%s", deviceId)
			pushed++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"pushed": pushed, "failed": failed})
}
