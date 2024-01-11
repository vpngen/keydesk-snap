package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpngen/keydesk-snap/core"
	"github.com/vpngen/keydesk-snap/core/crypto"
	"github.com/vpngen/keydesk-snap/core/snap"
	"github.com/vpngen/keydesk/kdlib/lockedfile"
	"github.com/vpngen/keydesk/keydesk/storage"
)

const (
	DefaultSnapEtcDir   = "/etc/vg-keydesk-snap"
	MaintenanceFileName = ".maintenance"
)

var (
	ErrEmptyTag       = fmt.Errorf("empty tag")
	ErrEmptyRealmFP   = fmt.Errorf("empty realm fingerprint")
	ErrInvalidRealmFP = fmt.Errorf("invalid realm fingerprint")
	ErrInvalidTime    = fmt.Errorf("invalid time")
)

type CommandOpts struct {
	BrigadeID    string
	EtcDir       string
	DbDir        string
	RealmFP      string
	Tag          string
	GlobalSnapAt time.Time
	Maintenance  int64
}

func main() {
	var w io.WriteCloser

	opts, err := parseArgs()
	if err != nil {
		log.Fatalf("Invalid flags: %s\n", err)
	}

	psk, err := readPSK()
	if err != nil {
		log.Fatalf("Read PSK: %s\n", err)
	}

	w = os.Stdout

	data, err := getSnapshot(opts, psk)
	if err != nil {
		log.Fatalf("Get snapshot: %s", err)
	}

	if _, err := w.Write(data); err != nil {
		log.Fatalf("Write snapshot: %s", err)
	}
}

func readPSK() ([]byte, error) {
	r := base64.NewDecoder(base64.StdEncoding, os.Stdin)

	psk, err := io.ReadAll(io.LimitReader(r, core.PSKSize))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return psk, nil
}

func writeMaintenanceFile(dir string, maintenance int64) error {
	if maintenance == 0 {
		return nil
	}

	f, err := os.OpenFile(filepath.Join(dir, MaintenanceFileName), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	defer f.Close()

	if _, err := fmt.Fprintf(f, "%d", maintenance); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func getSnapshot(opts *CommandOpts, psk []byte) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("empty options")
	}

	if opts.Maintenance != 0 {
		if err := writeMaintenanceFile(opts.DbDir, opts.Maintenance); err != nil {
			return nil, fmt.Errorf("write maintenance file: %w", err)
		}
	}

	realmKey, err := crypto.FindPubKeyInFile(opts.EtcDir, opts.RealmFP)
	if err != nil {
		return nil, fmt.Errorf("find realm key: %w", err)
	}

	authKeys, err := crypto.ReadAuthoritiesPubKeyFile(opts.EtcDir)
	if err != nil {
		return nil, fmt.Errorf("read authorities keys: %w", err)
	}

	var errIntegrity error

	data := &storage.Brigade{}
	filename := filepath.Join(opts.DbDir, storage.BrigadeFilename)

	f, err := lockedfile.OpenFile(filename, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	defer f.Close()

	pr, pw := io.Pipe()
	rt := io.TeeReader(f, pw)

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		if errIntegrity = json.NewDecoder(pr).Decode(data); errIntegrity != nil {
			return
		}

		if data.BrigadeID != opts.BrigadeID {
			errIntegrity = fmt.Errorf("%w: brigade id: %s", storage.ErrWrongStorageConfiguration, opts.BrigadeID)

			return
		}
	}()

	encriptedSnap, err := snap.MakeSnapshot(rt, snap.SnapOpts{
		Tag:          opts.Tag,
		BrigadeID:    opts.BrigadeID,
		GlobalSnapAt: opts.GlobalSnapAt,
		PSK:          psk,
		RealFP:       opts.RealmFP,
		RealmKey:     realmKey,
		AuthKeys:     authKeys,
	})
	if err != nil {
		pr.Close()

		return nil, fmt.Errorf("snapshot: %w", err)
	}

	wg.Wait()

	if errIntegrity != nil {
		return nil, fmt.Errorf("decode: %w", errIntegrity)
	}

	return encriptedSnap, nil
}

func parseArgs() (*CommandOpts, error) {
	var (
		id     string
		dbdir  string
		etcdir string
		err    error
	)

	sysUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("cannot define user: %w", err)
	}

	// is id only for debug?
	tag := flag.String("tag", "", "Tag for snapshot")
	snapAt := flag.String("stime", "", "Global snapshot time")
	realmFP := flag.String("rfp", "", "Realm fingerprint")
	maintenance := flag.Int64("mnt", 0, "Maintenance time (unix timestamp). Default: 0 (no maintenance)")
	brigadeID := flag.String("id", "", "BrigadeID (for test)")
	filedbDir := flag.String("d", "", "Dir for db files (for test). Default: "+storage.DefaultHomeDir+"/<BrigadeID>")
	etcDir := flag.String("c", "", "Dir for config files (for test). Default: "+DefaultSnapEtcDir)

	flag.Parse()

	if *tag == "" {
		return nil, ErrEmptyTag
	}

	if *realmFP == "" {
		return nil, ErrEmptyRealmFP
	}

	if !strings.HasPrefix(*realmFP, "SHA256:") {
		return nil, ErrInvalidRealmFP
	}

	buf, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(strings.TrimPrefix(*realmFP, "SHA256:"))
	if err != nil {
		return nil, fmt.Errorf("decode realm fingerprint: %w", err)
	}

	if len(buf) != 32 {
		return nil, ErrInvalidRealmFP
	}

	gst, err := strconv.ParseInt(*snapAt, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse snap time: %w", err)
	}

	if *filedbDir != "" {
		dbdir, err = filepath.Abs(*filedbDir)
		if err != nil {
			return nil, fmt.Errorf("dbdir dir: %w", err)
		}
	}

	if *etcDir != "" {
		etcdir, err = filepath.Abs(*etcDir)
		if err != nil {
			return nil, fmt.Errorf("etcdir dir: %w", err)
		}
	}

	switch *brigadeID {
	case "", sysUser.Username:
		id = sysUser.Username

		if *filedbDir == "" {
			dbdir = filepath.Join(storage.DefaultHomeDir, id)
		}
	default:
		id = *brigadeID

		cwd, err := os.Getwd()
		if err == nil {
			cwd, _ = filepath.Abs(cwd)
		}

		if *filedbDir == "" {
			dbdir = cwd
		}
	}

	return &CommandOpts{
		BrigadeID:    id,
		EtcDir:       etcdir,
		DbDir:        dbdir,
		RealmFP:      *realmFP,
		Tag:          *tag,
		GlobalSnapAt: time.Unix(gst, 0).UTC(),
		Maintenance:  *maintenance,
	}, nil
}
