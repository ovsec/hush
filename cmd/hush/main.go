// Command hush is a peer-to-peer secrets vault for small teams.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/ovsec/hush/internal/app"
	"github.com/ovsec/hush/internal/crypt"
	"github.com/ovsec/hush/internal/tui"
	"github.com/ovsec/hush/internal/vault"
	"github.com/ovsec/hush/internal/web"
)

var version = "0.1.0-dev"

const usage = `hush · a peer-to-peer secrets vault for small teams

usage
  hush                      open the vault (creates or joins one on first run)
  hush web [-port n] [-no-open]
                            open the vault in your browser (local only)
  hush daemon [-q]          stay unlocked and keep syncing: an always-on peer
  hush ls [-v]              list secrets
  hush get <title> [-f field] [-v]
                            print a field (password, username, url, notes)
  hush log                  show the signed log: what anyone holding the file can see

team
  hush code                 print your join code and safety number
  hush members              list members and their safety numbers
  hush add <join code>      add a member (admin)
  hush remove <name>        remove a member, rotate the key, re-encrypt (admin)
  hush export <file>        write a bundle for teammates (first join; sync does the rest)
  hush import <file>        verify and merge a bundle from a teammate

company login (OIDC)
  hush login -issuer <url> -client-id <id>
                            sign in and bind the login to your keys (before joining)
  hush sso                  show the vault's login policy
  hush sso set -issuer <url> -client-id <id> [-allow @co.com,…] [-require]
  hush sso off              remove the policy (admin)

  hush where                show where the vault lives on disk
  hush version

flags
  -v                        narrate every step (key derivation, decryption, ...) on stderr
  -sync internet|lan|off    peer-to-peer sync while unlocked (default internet)

environment
  HUSH_HOME                 vault directory (default ~/.hush)
  HUSH_SYNC                 default for -sync
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hush:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	svc := app.New(home())
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return cmdTUI(svc, args)
	}
	switch args[0] {
	case "daemon":
		return cmdDaemon(svc, args[1:])
	case "login":
		return cmdLogin(svc, args[1:])
	case "sso":
		return cmdSSO(svc, args[1:])
	case "ls", "list":
		return cmdList(svc, args[1:])
	case "get":
		return cmdGet(svc, args[1:])
	case "log":
		return cmdLog(svc)
	case "where":
		return cmdWhere(svc)
	case "web":
		return cmdWeb(svc, args[1:])
	case "code":
		return cmdCode(svc)
	case "members":
		return cmdMembers(svc)
	case "add":
		return cmdAdd(svc, args[1:])
	case "remove":
		return cmdRemove(svc, args[1:])
	case "export":
		return cmdExport(svc, args[1:])
	case "import":
		return cmdImport(svc, args[1:])
	case "version", "--version":
		fmt.Println("hush", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (try hush help)", args[0])
}

func home() string {
	if d := os.Getenv("HUSH_HOME"); d != "" {
		return d
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ".hush"
	}
	return filepath.Join(h, ".hush")
}

// parse accepts flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func narrate(svc *app.Service, on bool) {
	if !on {
		return
	}
	svc.Feed().SetHook(func(e app.Event) {
		fmt.Fprintf(os.Stderr, "  %-7s %s\n", e.Kind, e.Msg)
	})
}

func unlock(svc *app.Service) error {
	if !svc.Exists() {
		return app.ErrNoVault
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return errors.New("needs a terminal to read the passphrase")
	}
	fmt.Fprint(os.Stderr, "passphrase: ")
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	defer crypt.Wipe(pass)
	return svc.Unlock(pass)
}

func cmdList(svc *app.Service, args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "narrate")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	narrate(svc, *verbose)
	if err := unlock(svc); err != nil {
		return err
	}
	defer svc.Lock()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "TITLE\tUSERNAME\tUPDATED\tBY")
	for _, it := range svc.Items() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", it.Title, it.Username, it.Updated.Format("2006-01-02 15:04"), it.Author)
	}
	return tw.Flush()
}

func cmdGet(svc *app.Service, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	field := fs.String("f", "password", "field to print")
	verbose := fs.Bool("v", false, "narrate")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hush get <title> [-f field]")
	}
	narrate(svc, *verbose)
	if err := unlock(svc); err != nil {
		return err
	}
	defer svc.Lock()

	it, err := find(svc.Items(), pos[0])
	if err != nil {
		return err
	}
	e, err := svc.Reveal(it.ID)
	if err != nil {
		return err
	}
	values := map[string]string{"password": e.Password, "username": e.Username, "url": e.URL, "notes": e.Notes, "title": e.Title}
	v, ok := values[*field]
	if !ok {
		return fmt.Errorf("unknown field %q", *field)
	}
	fmt.Println(v)
	return nil
}

// find matches a title exactly (any case), then by unique substring.
func find(items []app.Item, q string) (app.Item, error) {
	ql := strings.ToLower(q)
	var hits []app.Item
	for _, it := range items {
		t := strings.ToLower(it.Title)
		if t == ql {
			return it, nil
		}
		if strings.Contains(t, ql) {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return app.Item{}, fmt.Errorf("no secret matches %q", q)
	case 1:
		return hits[0], nil
	}
	names := make([]string, len(hits))
	for i, h := range hits {
		names[i] = h.Title
	}
	return app.Item{}, fmt.Errorf("%q matches %s; be more specific", q, strings.Join(names, ", "))
}

func cmdLog(svc *app.Service) error {
	st, err := svc.PublicState()
	if err != nil {
		return err
	}
	fmt.Printf("%s · %d ops · every signature and hash link verified\n", app.OpsFile, len(st.Ops()))
	fmt.Println("Visible to anyone holding this file: vault and member names, op ids, times, authors, kinds, sizes.")
	fmt.Println("Not visible: titles, usernames, passwords, urls or notes.")
	fmt.Println()

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tOP\tTIME\tAUTHOR\tKIND\tDETAIL")
	for i, op := range st.Ops() {
		author := st.Members[op.Author].Name
		if author == "" {
			author = st.Removed[op.Author].Name
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", i+1, op.Short(),
			time.UnixMilli(op.Time).Format("2006-01-02 15:04:05"), author, op.Kind, describe(st, op.Kind, op.Body))
	}
	return tw.Flush()
}

func describe(st *vault.State, kind string, body json.RawMessage) string {
	switch kind {
	case vault.KindGenesis:
		var g vault.Genesis
		json.Unmarshal(body, &g)
		return fmt.Sprintf("vault %q · admin %s", g.Name, g.Admin.Name)
	case vault.KindKeyEpoch:
		var k vault.KeyEpoch
		json.Unmarshal(body, &k)
		return fmt.Sprintf("key epoch %d · sealed to %d member(s)", k.Epoch, len(k.Wrapped))
	case vault.KindPut:
		var p vault.SecretPut
		json.Unmarshal(body, &p)
		if p.Rekey {
			return fmt.Sprintf("entry %.8s · re-encrypted under epoch %d", p.Entry, p.Epoch)
		}
		return fmt.Sprintf("entry %.8s · %d B ciphertext · epoch %d", p.Entry, len(p.CT), p.Epoch)
	case vault.KindDelete:
		var d vault.SecretDelete
		json.Unmarshal(body, &d)
		return fmt.Sprintf("entry %.8s · tombstone", d.Entry)
	case vault.KindAdd:
		var a vault.AddMember
		json.Unmarshal(body, &a)
		login := ""
		if a.Member.SSO != nil {
			login = " · login " + a.Member.SSO.Email
		}
		return fmt.Sprintf("added %s · %s · %d key(s) sealed to them%s", a.Member.Name, crypt.FingerprintHex(a.Member.ID, a.Member.Box), len(a.Wrapped), login)
	case vault.KindSSO:
		var p vault.SSOPolicy
		json.Unmarshal(body, &p)
		if p.Issuer == "" {
			return "company login policy removed"
		}
		return fmt.Sprintf("company login at %s · require=%t · allow %v", p.Issuer, p.Require, p.Allow)
	case vault.KindRemove:
		var r vault.RemoveMember
		json.Unmarshal(body, &r)
		return fmt.Sprintf("removed %s · their key is no longer accepted", st.Removed[r.ID].Name)
	}
	return ""
}

func cmdWhere(svc *app.Service) error {
	fmt.Println(svc.Dir())
	for _, name := range []string{app.IdentityFile, app.OpsFile} {
		fi, err := os.Stat(filepath.Join(svc.Dir(), name))
		if err != nil {
			fmt.Printf("  %-14s missing\n", name)
			continue
		}
		fmt.Printf("  %-14s %6d B  %s\n", name, fi.Size(), fi.Mode().Perm())
	}
	return nil
}

func cmdCode(svc *app.Service) error {
	code, safety, err := svc.JoinCode()
	if err != nil {
		return err
	}
	fmt.Println(code)
	fmt.Fprintln(os.Stderr, "\nsafety number", safety)
	fmt.Fprintln(os.Stderr, "Send the code to your vault admin, then compare safety numbers with them.")
	return nil
}

func cmdMembers(svc *app.Service) error {
	members, err := svc.Members()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "NAME\tROLE\tSAFETY NUMBER\t")
	for _, m := range members {
		role, you := m.Role, ""
		if m.Removed {
			role = "removed"
		}
		if m.You {
			you = "you"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Name, role, m.Safety, you)
	}
	return tw.Flush()
}

func cmdAdd(svc *app.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hush add <join code>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := svc.CheckJoin(ctx, args[0])
	if err != nil {
		return err
	}
	if r.SSO != nil {
		fmt.Fprintf(os.Stderr, "%s signed in as %s (verified by %s)\n", r.Name, r.SSO.Email, r.SSO.Issuer)
	} else if r.Note != "" {
		fmt.Fprintln(os.Stderr, r.Note)
	}
	fmt.Fprintf(os.Stderr, "%s's safety number: %s\n", r.Name, r.Safety)
	if !confirm("Does it match exactly what " + r.Name + " sees?") {
		return errors.New("not added")
	}
	if err := unlock(svc); err != nil {
		return err
	}
	defer svc.Lock()
	if _, err := svc.AddMember(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s added. Send them a bundle (hush export <file>) so they can unlock; after that, sync keeps you both current.\n", r.Name)
	return nil
}

func cmdRemove(svc *app.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hush remove <name>")
	}
	members, err := svc.Members()
	if err != nil {
		return err
	}
	var hits []app.MemberInfo
	for _, m := range members {
		if !m.Removed && strings.EqualFold(m.Name, args[0]) {
			hits = append(hits, m)
		}
	}
	if len(hits) != 1 {
		return fmt.Errorf("%d current members are called %q", len(hits), args[0])
	}
	if !confirm("Remove " + hits[0].Name + " (" + hits[0].Safety + ")? This rotates the vault key and re-encrypts every secret.") {
		return errors.New("not removed")
	}
	if err := unlock(svc); err != nil {
		return err
	}
	defer svc.Lock()
	n, err := svc.RemoveMember(hits[0].ID)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s removed, %d secrets re-encrypted. They may have copied old values: change those passwords.\n", hits[0].Name, n)
	return nil
}

func cmdExport(svc *app.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hush export <file>")
	}
	n, err := svc.Export(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d ops written to %s (signed, encrypted; safe to send any way)\n", n, args[0])
	return nil
}

func cmdImport(svc *app.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hush import <file>")
	}
	res, err := svc.Import(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d new ops verified and merged, %d already known\n", res.Added, res.Known)
	for _, r := range res.Rejected {
		fmt.Fprintln(os.Stderr, "  rejected:", r)
	}
	return nil
}

func confirm(q string) bool {
	fmt.Fprint(os.Stderr, q+" [y/N] ")
	var answer string
	fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}

func cmdTUI(svc *app.Service, args []string) error {
	fs := flag.NewFlagSet("hush", flag.ContinueOnError)
	mode := syncFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	stop, err := startSync(svc, *mode)
	if err != nil {
		return err
	}
	defer stop()
	return tui.Run(svc)
}

func cmdWeb(svc *app.Service, args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	port := fs.Int("port", 0, "port on 127.0.0.1 (0 picks a free one)")
	noOpen := fs.Bool("no-open", false, "print the link instead of opening a browser")
	mode := syncFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	stopSync, err := startSync(svc, *mode)
	if err != nil {
		return err
	}
	defer stopSync()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return web.New(svc).Run(ctx, *port, func(url string) {
		fmt.Fprintln(os.Stderr, "hush web is running on this machine only. The link works once:")
		fmt.Fprintln(os.Stderr, " ", url)
		fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop; the vault locks when it does.")
		if !*noOpen {
			openBrowser(url)
		}
	})
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func cmdLogin(svc *app.Service, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	issuer := fs.String("issuer", os.Getenv("HUSH_SSO_ISSUER"), "OIDC issuer URL, from your admin")
	clientID := fs.String("client-id", os.Getenv("HUSH_SSO_CLIENT_ID"), "OIDC client id, from your admin")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *issuer == "" || *clientID == "" {
		return errors.New("usage: hush login -issuer <url> -client-id <id> (ask your vault admin for both)")
	}
	narrate(svc, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, err := svc.LinkLogin(ctx, *issuer, *clientID, func(url string) error {
		fmt.Fprintln(os.Stderr, "Sign in in your browser. If it did not open, visit:")
		fmt.Fprintln(os.Stderr, " ", url)
		openBrowser(url)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed in as %s. Your join code now carries this login: hush code\n", c.Email)
	return nil
}

func cmdSSO(svc *app.Service, args []string) error {
	if len(args) == 0 {
		p, err := svc.LoginPolicy()
		if err != nil {
			return err
		}
		if p == nil {
			fmt.Println("no company login policy; members are verified by safety number only")
			return nil
		}
		fmt.Printf("issuer     %s\nclient id  %s\nrequired   %t\nallowed    %s\n", p.Issuer, p.ClientID, p.Require, strings.Join(p.Allow, ", "))
		return nil
	}
	var pol vault.SSOPolicy
	switch args[0] {
	case "off":
	case "set":
		fs := flag.NewFlagSet("sso set", flag.ContinueOnError)
		issuer := fs.String("issuer", "", "OIDC issuer URL")
		clientID := fs.String("client-id", "", "OIDC client id (a public client allowing http://127.0.0.1 redirects)")
		allow := fs.String("allow", "", "comma-separated emails and @domains")
		require := fs.Bool("require", false, "refuse join codes without a login")
		if _, err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *issuer == "" || *clientID == "" {
			return errors.New("usage: hush sso set -issuer <url> -client-id <id> [-allow @co.com] [-require]")
		}
		pol = vault.SSOPolicy{Issuer: *issuer, ClientID: *clientID, Require: *require}
		for _, a := range strings.Split(*allow, ",") {
			if a = strings.TrimSpace(a); a != "" {
				pol.Allow = append(pol.Allow, a)
			}
		}
	default:
		return errors.New("usage: hush sso [set ... | off]")
	}
	narrate(svc, true)
	if err := unlock(svc); err != nil {
		return err
	}
	defer svc.Lock()
	return svc.SetLoginPolicy(pol)
}
