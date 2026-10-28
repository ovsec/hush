package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ovsec/hush/internal/app"
)

// ── welcome ─────────────────────────────────────────────────────────

func (m Model) keyWelcome(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "up", "k", "down", "j", "tab":
		m.choice = 1 - m.choice
	case "enter":
		if m.choice == 0 {
			m.toCreate()
		} else {
			m.toJoin()
		}
	}
	return m, nil
}

func (m Model) viewWelcome(w int) string {
	option := func(i int, title, desc string) string {
		marker, ts := "  ", sText
		if i == m.choice {
			marker, ts = sAccent.Render("▍ "), sBold
		}
		return marker + ts.Render(title) + "\n  " + sMuted.Render(trunc(desc, w-2))
	}
	return strings.Join([]string{
		sBold.Render("Welcome to hush"),
		sMuted.Render(trunc("A secrets vault for small teams. No server: your data lives on your devices.", w)),
		"",
		option(0, "Create a new vault", "you become its admin and can invite teammates"),
		"",
		option(1, "Join a team vault", "get a join code to send to your vault admin"),
		"",
		sFaint.Render(trunc("Everything will be stored in "+shortPath(m.svc.Dir()), w)),
	}, "\n")
}

// ── join ────────────────────────────────────────────────────────────

func (m *Model) toJoin() {
	m.scr, m.err = scrJoin, ""
	me := newInput("how teammates will see you", false)
	if u := os.Getenv("USER"); u != "" {
		me.SetValue(u)
	}
	m.setFields(me, newInput("at least 8 characters, a few words is best", true), newInput("type it again", true))
}

func (m Model) keyJoin(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.scr, m.err = scrWelcome, ""
		return m, nil
	case "tab", "down":
		return m.focusField(m.focus + 1)
	case "shift+tab", "up":
		return m.focusField(m.focus - 1)
	case "enter":
		if m.focus < len(m.fields)-1 {
			return m.focusField(m.focus + 1)
		}
		me := strings.TrimSpace(m.fields[0].Value())
		pass, confirm := m.fields[1].Value(), m.fields[2].Value()
		switch {
		case me == "":
			m.err = "tell teammates who you are"
		case len([]rune(pass)) < 8:
			m.err = "passphrase needs at least 8 characters"
		case pass != confirm:
			m.err = "passphrases do not match"
		default:
			svc := m.svc
			return m.startBusy("creating your identity", scrPending, func() error { return svc.Join(me, []byte(pass)) })
		}
		return m, nil
	}
	return m.updateInputs(k)
}

func (m Model) viewJoin(w int) string {
	return strings.Join([]string{
		sBold.Render("Join a team vault"),
		sMuted.Render(trunc("First, an identity for this machine. Your admin then adds it to the vault.", w)),
		"",
		m.fieldRow("your name", 0, ""),
		m.fieldRow("passphrase", 1, ""),
		m.fieldRow("confirm", 2, ""),
		"",
		m.steps(w, "what happens when you press enter", [][2]string{
			{"keygen", "generate an ed25519 signing key and an x25519 encryption key"},
			{"kdf", "stretch your passphrase with argon2id (64 MiB, 3 passes)"},
			{"seal", "encrypt your private keys into identity.json (mode 0600)"},
			{"ready", "sign a join code that carries only your public keys"},
		}),
	}, "\n")
}

// ── pending ─────────────────────────────────────────────────────────

func (m *Model) toPending() {
	m.scr, m.started = scrPending, time.Time{}
	code, safety, err := m.svc.JoinCode()
	if err != nil {
		m.err = err.Error()
	}
	m.code, m.safety = code, safety
	m.setFields(newInput("path to the bundle your admin sent, e.g. ~/Downloads/team.bundle", false))
}

func (m Model) keyPending(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+y":
		if err := clipboard.WriteAll(m.code); err != nil {
			m.err = "clipboard unavailable: " + err.Error()
			return m, nil
		}
		m.err, m.note = "", "join code copied · paste it to your admin"
		m.svc.Feed().Emit("clip", "join code copied · public: your name and public keys only")
		return m, nil
	case "enter":
		path := expandHome(strings.TrimSpace(m.fields[0].Value()))
		if path == "" {
			m.err = "enter the path of the bundle your admin sent"
			return m, nil
		}
		res, err := m.svc.Import(path)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		switch m.svc.Status() {
		case app.StatusReady:
			m.info, _ = m.svc.Info()
			m.toUnlock()
			m.note = fmt.Sprintf("you're in · %d ops verified · compare the admin's safety number, then unlock", res.Added)
		case app.StatusRemoved:
			m.err = app.ErrRemoved.Error()
		default:
			m.err = "bundle imported, but you are not in it yet: ask your admin to add you and export again"
		}
		return m, nil
	}
	return m.updateInputs(k)
}

func (m Model) viewPending(w int) string {
	code := lipgloss.NewStyle().Foreground(cAccent).Width(w - 2).PaddingLeft(2).Render(m.code)
	return strings.Join([]string{
		sBold.Render("Waiting to be added"),
		sMuted.Render(trunc("Send this join code to your vault admin. It holds only your name and public keys.", w)),
		"",
		code,
		"",
		sMuted.Render(pad("safety number", 15)) + sBold.Render(m.safety),
		sFaint.Render(trunc("Your admin sees this same number when adding you. Read it to each other on a call or in person.", w)),
		m.loginLine(w),
		"",
		sMuted.Render("then your admin exports a bundle and sends it to you"),
		m.fieldRow("bundle", 0, ""),
	}, "\n")
}

func (m Model) loginLine(w int) string {
	if email := m.svc.LoginEmail(); email != "" {
		return sCyan.Render("✓ ") + sMuted.Render(trunc("company login linked: "+email+" · it travels in your code", w-2))
	}
	return sFaint.Render(trunc("optional: prove your company login first with hush login -issuer … -client-id …", w))
}

func (m Model) adminLine(w int) string {
	switch {
	case m.info.Admin == "":
		return ""
	case m.info.IsAdmin:
		return sFaint.Render("you are the admin")
	}
	return sFaint.Render(trunc(fmt.Sprintf("admin %s · safety number %s · check it with them", m.info.Admin, m.info.AdminSafety), w))
}

// ── members ─────────────────────────────────────────────────────────

func (m *Model) toMembers() tea.Cmd {
	m.scr, m.mmode, m.request, m.fields, m.err = scrMembers, "", nil, nil, ""
	m.reloadMembers()
	return nil
}

func (m *Model) reloadMembers() {
	members, err := m.svc.Members()
	if err != nil {
		m.err = err.Error()
	}
	m.members = members
	m.mcur = max(0, min(m.mcur, len(members)-1))
	m.info, _ = m.svc.Info()
}

func (m Model) selectedMember() *app.MemberInfo {
	if m.mcur < len(m.members) {
		return &m.members[m.mcur]
	}
	return nil
}

func (m *Model) askPath(mode, placeholder, value string) tea.Cmd {
	in := newInput(placeholder, false)
	in.CharLimit = 4096
	in.SetValue(value)
	m.mmode, m.err, m.note = mode, "", ""
	m.setFields(in)
	m.fields[0].CursorEnd()
	return m.fields[0].Focus()
}

func (m Model) keyMembers(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	switch m.mmode {
	case "add", "export", "import":
		switch key {
		case "esc":
			m.mmode, m.fields = "", nil
			return m, nil
		case "enter":
			return m.submitMembers()
		}
		return m.updateInputs(k)

	case "confirm-add":
		m.mmode = ""
		if key == "y" {
			mem, err := m.svc.AddMember(m.fields[0].Value())
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			m.reloadMembers()
			m.note = mem.Name + " added · press s to export a bundle for them"
		}
		m.fields, m.request = nil, nil
		return m, nil

	case "confirm-remove":
		m.mmode = ""
		if sel := m.selectedMember(); key == "y" && sel != nil {
			n, err := m.svc.RemoveMember(sel.ID)
			if err != nil {
				m.err = err.Error()
				return m, nil
			}
			name := sel.Name
			m.reloadMembers()
			m.refresh()
			m.note = fmt.Sprintf("%s removed · %d secrets re-encrypted · change the ones marked !", name, n)
		}
		return m, nil
	}

	m.err, m.note = "", ""
	switch key {
	case "up", "k":
		m.mcur = max(0, m.mcur-1)
	case "down", "j":
		m.mcur = min(len(m.members)-1, m.mcur+1)
	case "a":
		if !m.info.IsAdmin {
			m.err = app.ErrNotAdmin.Error()
			return m, nil
		}
		return m, m.askPath("add", "paste the hush1:… code they sent you", "")
	case "r":
		sel := m.selectedMember()
		switch {
		case !m.info.IsAdmin:
			m.err = app.ErrNotAdmin.Error()
		case sel == nil || sel.Removed:
		case sel.You:
			m.err = "you cannot remove yourself"
		default:
			m.mmode = "confirm-remove"
		}
	case "s":
		return m, m.askPath("export", "where to save the bundle", shortPath(defaultBundle(m.info.Vault)))
	case "i":
		return m, m.askPath("import", "path to a bundle from a teammate", "")
	case "esc", "q", "m":
		m.toMain()
	}
	return m, nil
}

func (m Model) submitMembers() (tea.Model, tea.Cmd) {
	val := strings.TrimSpace(m.fields[0].Value())
	switch m.mmode {
	case "add":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r, err := m.svc.CheckJoin(ctx, val)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.err, m.request, m.mmode = "", &r, "confirm-add"
		m.fields[0].Blur()
		m.svc.Feed().Emit("verify", "join code from %q · self-signature ok · compare safety numbers now", r.Name)

	case "export":
		path := expandHome(val)
		n, err := m.svc.Export(path)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.mmode, m.fields = "", nil
		m.note = fmt.Sprintf("%d ops written to %s · send it any way you like", n, shortPath(path))

	case "import":
		res, err := m.svc.Import(expandHome(val))
		if errors.Is(err, app.ErrRemoved) {
			m.toUnlock()
			m.err = err.Error()
			return m, nil
		}
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.mmode, m.fields = "", nil
		m.reloadMembers()
		m.refresh()
		m.note = fmt.Sprintf("%d new ops merged · %d already known", res.Added, res.Known)
		if len(res.Rejected) > 0 {
			m.err = fmt.Sprintf("%d op(s) rejected: %s", len(res.Rejected), res.Rejected[0])
		}
	}
	return m, nil
}

func (m Model) membersFooter() string {
	switch m.mmode {
	case "add", "export", "import":
		return keys("enter", "ok", "esc", "cancel")
	case "confirm-add", "confirm-remove":
		return keys("y", "confirm", "any other key", "cancel")
	}
	if m.info.IsAdmin {
		return keys("↑↓", "move", "a", "add", "r", "remove", "s", "share bundle", "i", "import", "esc", "back")
	}
	return keys("↑↓", "move", "s", "share bundle", "i", "import", "esc", "back")
}

func (m Model) viewMembers(w int) string {
	who := "Only " + m.info.Admin + " can add or remove people."
	if m.info.IsAdmin {
		who = "You are the admin: you add and remove people."
	}
	lines := []string{
		sBold.Render("Members") + sMuted.Render(fmt.Sprintf("  ·  %d member(s) · key epoch %d", m.info.Members, m.info.Epoch)),
		sMuted.Render(trunc(who, w)),
		"",
	}
	nw := 4
	for _, mem := range m.members {
		nw = max(nw, min(18, len([]rune(mem.Name))))
	}
	for i, mem := range m.members {
		marker, ns, rest := "  ", sText, sMuted
		if i == m.mcur {
			marker, ns = sAccent.Render("▍ "), sBold
		}
		role := mem.Role
		if mem.Removed {
			ns, rest, role = sFaint, sFaint, "removed"
		}
		line := marker + ns.Render(pad(trunc(mem.Name, nw), nw+2)) + rest.Render(pad(role, 9)) + rest.Render(pad(mem.Safety, 25))
		line += presence(mem)
		lines = append(lines, line)
	}
	if sel := m.selectedMember(); sel != nil && sel.SSO != nil {
		lines = append(lines, "", sFaint.Render(trunc(fmt.Sprintf("%s · company login %s · verified by %s", sel.Name, sel.SSO.Email, host(sel.SSO.Issuer)), w)))
	}
	lines = append(lines, "")

	switch m.mmode {
	case "add":
		lines = append(lines, sText.Render("Paste their join code"), m.fieldRow("join code", 0, ""))
	case "confirm-add":
		r := m.request
		lines = append(lines,
			sBold.Render(trunc(fmt.Sprintf("Add %q?", r.Name), w)),
			sMuted.Render(pad("safety number", 15))+sBrand.Render(r.Safety),
		)
		if r.SSO != nil {
			lines = append(lines, sMuted.Render(pad("company login", 15))+sCyan.Render(trunc("✓ "+r.SSO.Email+" · verified by "+host(r.SSO.Issuer), w-15)))
		} else if r.Note != "" {
			lines = append(lines, sFaint.Render(trunc(r.Note, w)))
		}
		lines = append(lines, sMuted.Render(trunc("Ask "+r.Name+" to read the number on their screen. Add only if every digit matches.", w)))
	case "confirm-remove":
		sel := m.selectedMember()
		lines = append(lines,
			sDanger.Render(trunc(fmt.Sprintf("Remove %q?", sel.Name), w)),
			sFaint.Render(trunc("· their key stops being accepted wherever this log goes", w)),
			sFaint.Render(trunc(fmt.Sprintf("· a new vault key (epoch %d) is sealed to the other %d member(s)", m.info.Epoch+1, m.info.Members-1), w)),
			sFaint.Render(trunc(fmt.Sprintf("· all %d secrets are re-encrypted with it", m.info.Secrets), w)),
			sFaint.Render(trunc("· they may have copied old values: those get marked ! so you can change them", w)),
		)
	case "export":
		lines = append(lines, sText.Render("Write a bundle for your teammates"), m.fieldRow("save to", 0, ""),
			sFaint.Render(trunc("Signed, encrypted ops only. Send it any way you like: chat, email, USB.", w)))
	case "import":
		lines = append(lines, sText.Render("Merge a bundle from a teammate"), m.fieldRow("bundle", 0, ""),
			sFaint.Render(trunc("Every op's signature and permissions are checked before anything is merged.", w)))
	default:
		lines = append(lines,
			rule("under the hood", w),
			sFaint.Render(trunc("people are named by their ed25519 key; the safety number covers both public keys", w)),
			sFaint.Render(trunc("adding seals every vault key to the newcomer's x25519 key", w)),
			sFaint.Render(trunc("removing seals a new key to everyone else and re-encrypts every secret", w)),
			sFaint.Render(trunc("bundles carry signed ops; each one is verified before it is merged", w)),
			sFaint.Render(trunc("presence is live while sync runs: peers connect directly or through a member relay", w)),
		)
	}
	return strings.Join(lines, "\n")
}

// presence renders a member's live state, or their last activity when sync
// is off.
func presence(mem app.MemberInfo) string {
	seen := func(t time.Time, verb string) string {
		if t.IsZero() {
			return "never " + verb
		}
		return verb + " " + ago(t)
	}
	switch {
	case mem.Removed:
		return ""
	case mem.You:
		return sCyan.Render("● you")
	case mem.Presence == "direct":
		return sCyan.Render("● online · direct")
	case mem.Presence == "relay":
		return sCyan.Render("◐ online · via relay")
	case mem.Presence == "offline":
		return sFaint.Render("○ offline · " + seen(mem.LastSeen, "seen"))
	}
	return sFaint.Render("○ " + seen(mem.LastActive, "active"))
}

// online counts other members currently connected, and other members.
func online(members []app.MemberInfo) (on, others int, syncing bool) {
	for _, mem := range members {
		if mem.You || mem.Removed {
			continue
		}
		others++
		if mem.Presence != "" {
			syncing = true
		}
		if mem.Presence == "direct" || mem.Presence == "relay" {
			on++
		}
	}
	return on, others, syncing
}

func host(issuer string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if i := strings.IndexByte(h, '/'); i > 0 {
		h = h[:i]
	}
	return h
}

// ── helpers ─────────────────────────────────────────────────────────

func shortPath(p string) string {
	if h, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(h, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.Join("~", rel)
		}
	}
	return p
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~"); ok {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, rest)
		}
	}
	return p
}

func defaultBundle(vaultName string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '-'
	}, vaultName)
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "hush-"+strings.Trim(slug, "-")+".bundle")
}
