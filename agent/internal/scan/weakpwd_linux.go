//go:build linux

package scan

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/openwall/yescrypt-go"
	crypt "github.com/sergeymakinen/go-crypt"
	"github.com/sergeymakinen/go-crypt/md5"
	"github.com/sergeymakinen/go-crypt/sha256"
	"github.com/sergeymakinen/go-crypt/sha512"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
)

const maxIdentityBytes = 4 << 20
const maxAccounts = 4096
const maxCandidates = 10000

var accountName = regexp.MustCompile(`^[a-zA-Z0-9_.][a-zA-Z0-9_.@$-]{0,127}$`)
var cryptChars = regexp.MustCompile(`^[./0-9A-Za-z]+$`)
var nologinShells = map[string]bool{"/sbin/nologin": true, "/usr/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true, "/bin/sync": true}

type localAccount struct {
	name, hash, shell string
	uid               uint64
	last              int64
}

func WeakPasswordContract() uint32 { return 1 }
func detectWeakPasswords(ctx context.Context, pace func(context.Context) error) ([]*pb.WeakPwdFinding, *pb.WeakPasswordCoverage) {
	return scanLocalPasswords(ctx, "/etc/passwd", "/etc/shadow", pace)
}

// Open before inspection; never read a symlink/FIFO/device or expose contents
// or native errors in evidence. Fixed system paths only in production.
func readIdentity(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("identity_read_failed")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size > maxIdentityBytes {
		return nil, errors.New("identity_metadata_invalid")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxIdentityBytes+1))
	if err != nil || len(b) > maxIdentityBytes || len(b) == 0 {
		return nil, errors.New("identity_read_failed")
	}
	return b, nil
}

func parseIdentities(passwd, shadow []byte) ([]localAccount, error) {
	accounts := map[string]localAccount{}
	for _, line := range strings.Split(strings.TrimSuffix(string(passwd), "\n"), "\n") {
		p := strings.Split(line, ":")
		if len(p) != 7 || !accountName.MatchString(p[0]) || len(line) > 8192 {
			return nil, errors.New("identity_parse_failed")
		}
		if _, exists := accounts[p[0]]; exists {
			return nil, errors.New("identity_duplicate")
		}
		uid, e := strconv.ParseUint(p[2], 10, 32)
		if e != nil {
			return nil, errors.New("identity_parse_failed")
		}
		if _, e = strconv.ParseUint(p[3], 10, 32); e != nil {
			return nil, errors.New("identity_parse_failed")
		}
		if p[1] != "x" {
			return nil, errors.New("passwd_credential_source_unsupported")
		}
		accounts[p[0]] = localAccount{name: p[0], uid: uid, shell: p[6], last: -1}
		if len(accounts) > maxAccounts {
			return nil, errors.New("account_limit")
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(shadow), "\n"), "\n") {
		p := strings.Split(line, ":")
		if len(p) != 9 || len(line) > 8192 || !accountName.MatchString(p[0]) || seen[p[0]] {
			return nil, errors.New("identity_parse_failed")
		}
		a, ok := accounts[p[0]]
		if !ok {
			return nil, errors.New("identity_account_mismatch")
		}
		seen[p[0]] = true
		a.hash = p[1]
		for _, v := range p[2:8] {
			if v != "" {
				n, e := strconv.ParseInt(v, 10, 32)
				if e != nil || n < -1 {
					return nil, errors.New("identity_parse_failed")
				}
			}
		}
		if p[2] != "" {
			a.last, _ = strconv.ParseInt(p[2], 10, 32)
		}
		accounts[p[0]] = a
	}
	if len(seen) != len(accounts) {
		return nil, errors.New("identity_account_mismatch")
	}
	out := make([]localAccount, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// Validate every parameter before the library can allocate or start a KDF.
func hashAlgorithm(hash string) (string, error) {
	if len(hash) > 256 {
		return "", errors.New("hash_invalid")
	}
	p := strings.Split(hash, "$")
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		if len(hash) != 60 || len(p) != 4 || len(p[3]) != 53 || !cryptChars.MatchString(p[3]) {
			return "", errors.New("hash_invalid")
		}
		cost, e := bcrypt.Cost([]byte(hash))
		if e != nil {
			return "", errors.New("hash_invalid")
		}
		if cost > 10 {
			return "", errors.New("hash_cost_exceeded")
		}
		return "bcrypt", nil
	}
	if len(p) < 4 || p[0] != "" {
		return "", errors.New("hash_unsupported")
	}
	if p[1] == "y" {
		if len(p) != 5 || len(p[3]) < 1 || len(p[3]) > 86 || len(p[4]) != 43 || !cryptChars.MatchString(p[3]) || !cryptChars.MatchString(p[4]) {
			return "", errors.New("hash_invalid")
		}
		// libxcrypt default j9T: N=4096,r=32,p=1 (~16 MiB). Reject all other costs.
		if p[2] != "j9T" {
			return "", errors.New("hash_cost_unsupported")
		}
		return "yescrypt", nil
	}
	if p[1] != "1" && p[1] != "5" && p[1] != "6" {
		return "", errors.New("hash_unsupported")
	}
	i := 2
	if len(p) == 5 && (p[1] == "5" || p[1] == "6") && strings.HasPrefix(p[2], "rounds=") {
		n, e := strconv.ParseUint(strings.TrimPrefix(p[2], "rounds="), 10, 32)
		if e != nil || n < 1000 {
			return "", errors.New("hash_invalid")
		}
		if n > 100000 {
			return "", errors.New("hash_cost_exceeded")
		}
		i = 3
	}
	saltMax, sumLen := 16, 86
	if p[1] == "1" {
		saltMax, sumLen = 8, 22
	}
	if p[1] == "5" {
		sumLen = 43
	}
	if len(p) != i+2 || len(p[i]) > saltMax || len(p[i]) == 0 || !cryptChars.MatchString(p[i]) || len(p[i+1]) != sumLen || !cryptChars.MatchString(p[i+1]) {
		return "", errors.New("hash_invalid")
	}
	return map[string]string{"1": "md5crypt", "5": "sha256crypt", "6": "sha512crypt"}[p[1]], nil
}
func checkCandidate(hash, password, algorithm string) (bool, error) {
	var err error
	switch algorithm {
	case "md5crypt":
		err = md5.Check(hash, password)
	case "sha256crypt":
		err = sha256.Check(hash, password)
	case "sha512crypt":
		err = sha512.Check(hash, password)
	case "bcrypt":
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
	case "yescrypt":
		b, e := yescrypt.Hash([]byte(password), []byte(hash))
		if e != nil {
			return false, errors.New("hash_verification_failed")
		}
		return subtle.ConstantTimeCompare(b, []byte(hash)) == 1, nil
	default:
		return false, errors.New("hash_unsupported")
	}
	if errors.Is(err, crypt.ErrPasswordMismatch) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("hash_verification_failed")
	}
	return true, nil
}

func scanLocalPasswords(ctx context.Context, passwdPath, shadowPath string, pace func(context.Context) error) (findings []*pb.WeakPwdFinding, coverage *pb.WeakPasswordCoverage) {
	start := time.Now()
	coverage = &pb.WeakPasswordCoverage{Status: "failed", DictionaryVersion: DictionaryVersion, DictionarySha256: DictionarySHA256}
	defer func() { coverage.DurationMs = uint64(time.Since(start).Milliseconds()) }()
	issue := func(code string) {
		for _, s := range coverage.Issues {
			if s == code {
				return
			}
		}
		if len(coverage.Issues) < 32 {
			coverage.Issues = append(coverage.Issues, code)
		}
	}
	p, e := readIdentity(passwdPath)
	if e != nil {
		issue(e.Error())
		return
	}
	defer clear(p)
	s, e := readIdentity(shadowPath)
	if e != nil {
		issue(e.Error())
		return
	}
	defer clear(s)
	accounts, e := parseIdentities(p, s)
	if e != nil {
		issue(e.Error())
		return
	}
	coverage.AccountsSeen = uint32(len(accounts))
	coverage.Status = "complete"
	add := func(a localAccount, kind string) {
		findings = append(findings, &pb.WeakPwdFinding{Account: a.name, Type: kind})
	}
	for index, a := range accounts {
		if ctx.Err() != nil || coverage.CandidatesTested >= maxCandidates {
			coverage.AccountsFailed += uint32(len(accounts) - index)
			issue("scan_budget_exhausted")
			break
		}
		if a.uid == 0 && a.name != "root" {
			add(a, "uid0_nonroot")
		}
		if strings.HasPrefix(a.hash, "!") || strings.HasPrefix(a.hash, "*") || nologinShells[a.shell] {
			coverage.AccountsExcluded++
			continue
		}
		if a.hash == "" {
			add(a, "system_empty")
			coverage.AccountsChecked++
			continue
		}
		algorithm, err := hashAlgorithm(a.hash)
		if err != nil {
			if err.Error() == "hash_invalid" {
				coverage.AccountsFailed++
			} else {
				coverage.AccountsUnsupported++
			}
			issue(err.Error())
			continue
		}
		checked := false
		for i, candidate := range dictionary {
			if ctx.Err() != nil || coverage.CandidatesTested >= maxCandidates {
				issue("scan_budget_exhausted")
				break
			}
			if pace != nil {
				if pace(ctx) != nil {
					issue("scan_budget_exhausted")
					break
				}
			}
			hashStart := time.Now()
			match, err := checkCandidate(a.hash, candidate, algorithm)
			coverage.CandidatesTested++
			if pace != nil {
				timer := time.NewTimer(4 * time.Since(hashStart))
				select {
				case <-ctx.Done():
					timer.Stop()
				case <-timer.C:
				}
			}
			if err != nil {
				issue("hash_verification_failed")
				break
			}
			if match {
				add(a, "system_weak")
				checked = true
				break
			}
			if i == len(dictionary)-1 {
				checked = true
			}
		}
		if checked {
			coverage.AccountsChecked++
		} else {
			coverage.AccountsFailed++
		}
		if a.last > 0 && time.Now().Unix()/86400-a.last > 90 {
			add(a, "pwd_stale")
		}
	}
	if coverage.AccountsUnsupported > 0 || coverage.AccountsFailed > 0 {
		coverage.Status = "partial"
	}
	// A credential-file change invalidates the snapshot, including previous hits.
	p2, e1 := readIdentity(passwdPath)
	s2, e2 := readIdentity(shadowPath)
	stable := e1 == nil && e2 == nil && bytes.Equal(p, p2) && bytes.Equal(s, s2)
	clear(p2)
	clear(s2)
	if !stable {
		findings = nil
		coverage.Status = "failed"
		issue("identity_changed")
	}
	return
}
