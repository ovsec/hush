// Package tui is hush's terminal interface. It keeps an activity panel on
// screen so every key derivation, decryption, signature and disk write the
// service performs is visible as it happens.
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ovsec/hush/internal/app"
)

const (
	autoLock  = 5 * time.Minute
	clipClear = 30 * time.Second
	genLength = 24
)

type screen int

const (
	scrWelcome screen = iota
	scrCreate
	scrJoin
	scrPending
	scrMembers
	scrUnlock
	scrMain
	scrEdit
	scrRaw
	scrConfirm
)

type (
	eventMsg app.Event
	tickMsg  time.Time
	doneMsg  struct {
		err  error
		next screen
	}
	clearClipMsg struct{ gen int }
)

// Model is the whole UI state.
type Model struct {
	svc    *app.Service
	events <-chan app.Event
	info   app.Info
	w, h   int
	scr    screen

	busy    string
	started time.Time
	spin    spinner.Model
	err     string
	note    string

	fields []textinput.Model
	focus  int

	items     []app.Item
	view      []app.Item
	cursor    int
	search    textinput.Model
	searching bool
	open      *app.Entry
	openID    string
	showPass  bool
	activity  bool

	choice  int
	members []app.MemberInfo
	mcur    int
	mmode   string
	request *app.JoinCheck
	code    string
	safety  string

	editID  string
	raw     []string
	rawTop  int
	idle    time.Time
	clipVal string
	clipGen int
}

// Run starts the TUI and locks the vault when it exits.
func Run(svc *app.Service) error {
	final, err := tea.NewProgram(New(svc), tea.WithAltScreen()).Run()
	if m, ok := final.(Model); ok && m.clipVal != "" {
		if cur, _ := clipboard.ReadAll(); cur == m.clipVal {
			_ = clipboard.WriteAll("")
		}
	}
	svc.Lock()
	return err
}

// New builds the first screen: create if there is no vault, unlock otherwise.
func New(svc *app.Service) Model {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = sAccent
	search := newInput("search", false)
	search.Prompt = "/ "
	search.PromptStyle = sAccent

	events, _ := svc.Feed().Subscribe()
	m := Model{svc: svc, events: events, spin: sp, search: search, activity: true, w: 80, h: 24, idle: time.Now()}
	switch svc.Status() {
	case app.StatusNone:
		m.scr = scrWelcome
	case app.StatusPending:
		m.toPending()
	default:
		info, err := svc.Info()
		m.info = info
		if err != nil {
			m.err = err.Error()
		}
		m.toUnlock()
	}
	return m
}

func newInput(placeholder string, secret bool) textinput.Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = placeholder
	ti.PlaceholderStyle = sFaint
	ti.TextStyle = sText
	ti.Cursor.Style = sAccent
	ti.CharLimit = 1024
	ti.Width = 40
	if secret {
		ti.EchoMode = textinput.EchoPassword
		ti.EchoCharacter = '•'
	}
	return ti
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.waitEvent(), tick())
}

func (m Model) waitEvent() tea.Cmd {
	ch := m.events
	return func() tea.Msg { return eventMsg(<-ch) }
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ── screen transitions ──────────────────────────────────────────────

func (m *Model) setFields(fs ...textinput.Model) {
	m.fields, m.focus = fs, 0
	m.sizeInputs()
	m.fields[0].Focus()
}

func (m *Model) toCreate() {
	m.scr = scrCreate
	name := newInput("e.g. team-infra", false)
	me := newInput("how teammates will see you", false)
	if u := os.Getenv("USER"); u != "" {
		me.SetValue(u)
	}
	m.setFields(name, me, newInput("at least 8 characters, a few words is best", true), newInput("type it again", true))
}

func (m *Model) toUnlock() {
	m.scr, m.started = scrUnlock, time.Time{}
	m.info, _ = m.svc.Info()
	m.items, m.view, m.open, m.openID, m.showPass = nil, nil, nil, "", false
	m.setFields(newInput("type it and press enter", true))
}

func (m *Model) toMain() {
	m.scr = scrMain
	m.fields = nil
	m.info, _ = m.svc.Info()
	m.refresh()
}

func (m *Model) toEdit(id string, e app.Entry) tea.Cmd {
	m.scr, m.editID, m.err, m.note = scrEdit, id, "", ""
	title := newInput("github, aws root, prod db…", false)
	user := newInput("optional", false)
	pw := newInput("ctrl+g to generate", true)
	url := newInput("optional", false)
	notes := newInput("optional", false)
	notes.CharLimit = 4096
	title.SetValue(e.Title)
	user.SetValue(e.Username)
	pw.SetValue(e.Password)
	url.SetValue(e.URL)
	notes.SetValue(e.Notes)
	m.setFields(title, user, pw, url, notes)
	return textinput.Blink
}

func (m *Model) sizeInputs() {
	w := max(16, min(52, m.w-22))
	for i := range m.fields {
		m.fields[i].Width = w
	}
	m.search.Width = max(10, min(36, m.w*2/5-4))
}

func (m *Model) refresh() {
	m.items = m.svc.Items()
	m.filter()
}

func (m *Model) filter() {
	q := strings.ToLower(strings.TrimSpace(m.search.Value()))
	m.view = nil
	for _, it := range m.items {
		hay := strings.ToLower(it.Title + " " + it.Username + " " + it.URL)
		if q == "" || strings.Contains(hay, q) {
			m.view = append(m.view, it)
		}
	}
	m.cursor = max(0, min(m.cursor, len(m.view)-1))
}

func (m *Model) selectID(id string) {
	for i, it := range m.view {
		if it.ID == id {
			m.cursor = i
		}
	}
}

func (m Model) selected() *app.Item {
	if m.cursor < len(m.view) {
		return &m.view[m.cursor]
	}
	return nil
}

// ── update ──────────────────────────────────────────────────────────

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.sizeInputs()
		return m, nil

	case eventMsg:
		switch msg.Kind {
		case "merge", "online", "offline":
			if m.svc.Unlocked() {
				m.refresh()
				if m.scr == scrMembers && m.mmode == "" {
					m.reloadMembers()
				}
			}
		case "lock":
			if !m.svc.Unlocked() && m.scr != scrUnlock && m.scr != scrPending && m.scr != scrWelcome {
				m.toUnlock()
				m.err = msg.Msg
			}
		}
		return m, m.waitEvent()

	case tickMsg:
		if m.svc.Unlocked() && time.Since(m.idle) > autoLock {
			m.svc.Lock()
			m.toUnlock()
			m.note = "locked after 5 minutes idle"
		}
		return m, tick()

	case spinner.TickMsg:
		if m.busy == "" {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case doneMsg:
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
			if m.scr == scrUnlock {
				m.fields[0].SetValue("")
			}
			return m, nil
		}
		m.err, m.note = "", ""
		if msg.next == scrPending {
			m.toPending()
		} else {
			m.toMain()
		}
		return m, nil

	case clearClipMsg:
		if msg.gen == m.clipGen && m.clipVal != "" {
			if cur, err := clipboard.ReadAll(); err == nil && cur == m.clipVal {
				_ = clipboard.WriteAll("")
				m.svc.Feed().Emit("clip", "clipboard cleared")
			} else {
				m.svc.Feed().Emit("clip", "clipboard changed since copy · left alone")
			}
			m.clipVal = ""
		}
		return m, nil

	case tea.KeyMsg:
		m.idle = time.Now()
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.busy != "" {
			return m, nil
		}
		switch m.scr {
		case scrWelcome:
			return m.keyWelcome(msg)
		case scrJoin:
			return m.keyJoin(msg)
		case scrPending:
			return m.keyPending(msg)
		case scrMembers:
			return m.keyMembers(msg)
		case scrCreate:
			return m.keyCreate(msg)
		case scrUnlock:
			return m.keyUnlock(msg)
		case scrMain:
			return m.keyMain(msg)
		case scrEdit:
			return m.keyEdit(msg)
		case scrRaw:
			return m.keyRaw(msg)
		case scrConfirm:
			return m.keyConfirm(msg)
		}
	}
	return m.updateInputs(msg)
}

func (m Model) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	if m.focus < len(m.fields) {
		var cmd tea.Cmd
		m.fields[m.focus], cmd = m.fields[m.focus].Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.searching {
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m Model) focusField(i int) (tea.Model, tea.Cmd) {
	n := len(m.fields)
	m.fields[m.focus].Blur()
	m.focus = (i%n + n) % n
	return m, m.fields[m.focus].Focus()
}

func (m Model) startBusy(label string, next screen, run func() error) (tea.Model, tea.Cmd) {
	m.err, m.note, m.busy, m.started = "", "", label, time.Now()
	return m, tea.Batch(m.spin.Tick, func() tea.Msg { return doneMsg{err: run(), next: next} })
}

func (m Model) keyCreate(k tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		name := strings.TrimSpace(m.fields[0].Value())
		me := strings.TrimSpace(m.fields[1].Value())
		pass, confirm := m.fields[2].Value(), m.fields[3].Value()
		switch {
		case name == "":
			m.err = "give the vault a name"
		case me == "":
			m.err = "tell teammates who you are"
		case len([]rune(pass)) < 8:
			m.err = "passphrase needs at least 8 characters"
		case pass != confirm:
			m.err = "passphrases do not match"
		default:
			svc := m.svc
			return m.startBusy("creating vault", scrMain, func() error { return svc.Create(name, me, []byte(pass)) })
		}
		return m, nil
	}
	return m.updateInputs(k)
}

func (m Model) keyUnlock(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.String() == "enter" {
		pass := []byte(m.fields[0].Value())
		m.fields[0].SetValue("")
		svc := m.svc
		return m.startBusy("unlocking", scrMain, func() error { return svc.Unlock(pass) })
	}
	return m.updateInputs(k)
}

func (m Model) keyMain(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searching {
		switch k.String() {
		case "esc":
			m.searching = false
			m.search.SetValue("")
			m.search.Blur()
			m.filter()
			return m, nil
		case "enter", "down", "up":
			m.searching = false
			m.search.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(k)
		m.filter()
		m.closeEntry()
		return m, cmd
	}

	m.err, m.note = "", ""
	switch k.String() {
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "home", "g":
		m.move(-len(m.view))
	case "end", "G":
		m.move(len(m.view))
	case "/":
		m.searching = true
		return m, m.search.Focus()
	case "esc":
		if m.open != nil {
			m.closeEntry()
		} else if m.search.Value() != "" {
			m.search.SetValue("")
			m.filter()
		}
	case "enter", " ":
		m.reveal()
	case "p":
		if m.reveal() {
			m.showPass = !m.showPass
		}
	case "c":
		return m.copy("password")
	case "u":
		return m.copy("username")
	case "n":
		return m, m.toEdit("", app.Entry{})
	case "e":
		if it := m.selected(); it != nil && m.reveal() {
			return m, m.toEdit(it.ID, *m.open)
		}
	case "d":
		if m.selected() != nil {
			m.scr = scrConfirm
		}
	case "x":
		if it := m.selected(); it != nil {
			raw, err := m.svc.Raw(it.ID)
			if err != nil {
				m.err = err.Error()
				break
			}
			m.raw, m.rawTop, m.scr = strings.Split(raw, "\n"), 0, scrRaw
		}
	case "a":
		m.activity = !m.activity
	case "m":
		return m, m.toMembers()
	case "l":
		m.svc.Lock()
		m.toUnlock()
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m *Model) move(d int) {
	next := max(0, min(len(m.view)-1, m.cursor+d))
	if next != m.cursor {
		m.cursor = next
		m.closeEntry()
	}
}

func (m *Model) closeEntry() { m.open, m.openID, m.showPass = nil, "", false }

// reveal decrypts the selected entry if it is not already open.
func (m *Model) reveal() bool {
	it := m.selected()
	if it == nil {
		return false
	}
	if m.open != nil && m.openID == it.ID {
		return true
	}
	e, err := m.svc.Reveal(it.ID)
	if err != nil {
		m.err = err.Error()
		return false
	}
	m.open, m.openID, m.showPass = &e, it.ID, false
	return true
}

func (m Model) copy(field string) (tea.Model, tea.Cmd) {
	if !m.reveal() {
		return m, nil
	}
	val := m.open.Password
	if field == "username" {
		val = m.open.Username
	}
	if val == "" {
		m.note = "no " + field + " to copy"
		return m, nil
	}
	if err := clipboard.WriteAll(val); err != nil {
		m.err = "clipboard unavailable: " + err.Error()
		return m, nil
	}
	m.clipVal = val
	m.clipGen++
	gen := m.clipGen
	m.note = fmt.Sprintf("%s copied · clears in %s", field, clipClear)
	m.svc.Feed().Emit("clip", "%s of %q copied · auto-clear in %s", field, m.open.Title, clipClear)
	return m, tea.Tick(clipClear, func(time.Time) tea.Msg { return clearClipMsg{gen} })
}

func (m Model) keyEdit(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.scr, m.fields, m.err = scrMain, nil, ""
		return m, nil
	case "tab", "down":
		return m.focusField(m.focus + 1)
	case "shift+tab", "up":
		return m.focusField(m.focus - 1)
	case "ctrl+g":
		m.fields[2].SetValue(m.svc.GeneratePassword(genLength))
		m.fields[2].CursorEnd()
		return m, nil
	case "ctrl+r":
		if m.fields[2].EchoMode == textinput.EchoPassword {
			m.fields[2].EchoMode = textinput.EchoNormal
		} else {
			m.fields[2].EchoMode = textinput.EchoPassword
		}
		return m, nil
	case "enter", "ctrl+s":
		if k.String() == "enter" && m.focus < len(m.fields)-1 {
			return m.focusField(m.focus + 1)
		}
		e := app.Entry{
			Title:    m.fields[0].Value(),
			Username: strings.TrimSpace(m.fields[1].Value()),
			Password: m.fields[2].Value(),
			URL:      strings.TrimSpace(m.fields[3].Value()),
			Notes:    m.fields[4].Value(),
		}
		id, err := m.svc.Save(m.editID, e)
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.toMain()
		m.selectID(id)
		m.closeEntry()
		m.note = "saved · encrypted, signed and written"
		return m, nil
	}
	return m.updateInputs(k)
}

func (m Model) keyRaw(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc", "x", "q":
		m.scr, m.raw = scrMain, nil
	case "up", "k":
		m.rawTop = max(0, m.rawTop-1)
	case "down", "j":
		m.rawTop = min(max(0, len(m.raw)-1), m.rawTop+1)
	}
	return m, nil
}

func (m Model) keyConfirm(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.scr = scrMain
	if k.String() != "y" {
		return m, nil
	}
	if it := m.selected(); it != nil {
		if err := m.svc.Delete(it.ID); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.closeEntry()
		m.refresh()
		m.note = "deleted"
	}
	return m, nil
}

// ── view ────────────────────────────────────────────────────────────

func (m Model) View() string {
	w := max(20, m.w-4)
	actN := m.activityRows()
	ch := m.h - 6
	if actN > 0 {
		ch -= actN + 2
	}
	ch = max(3, ch)

	var content, footer string
	switch m.scr {
	case scrWelcome:
		content = m.viewWelcome(w)
		footer = keys("↑↓", "choose", "enter", "continue", "ctrl+c", "quit")
	case scrJoin:
		content = m.viewJoin(w)
		footer = keys("enter", "next", "tab", "move", "esc", "back", "ctrl+c", "quit")
	case scrPending:
		content = m.viewPending(w)
		footer = keys("ctrl+y", "copy code", "enter", "import bundle", "ctrl+c", "quit")
	case scrMembers:
		content = m.viewMembers(w)
		footer = m.membersFooter()
	case scrCreate:
		content = m.viewCreate(w)
		footer = keys("enter", "next", "tab", "move", "esc", "back", "ctrl+c", "quit")
	case scrUnlock:
		content = m.viewUnlock(w)
		footer = keys("enter", "unlock", "ctrl+c", "quit")
	case scrMain, scrConfirm:
		content = m.viewMain(w, ch)
		footer = keys("↑↓", "move", "/", "find", "n", "new", "m", "members", "a", "activity", "l", "lock", "q", "quit")
		if m.scr == scrConfirm {
			footer = keys("y", "delete", "any other key", "cancel")
		}
	case scrEdit:
		content = m.viewEdit(w)
		footer = keys("ctrl+s", "save", "tab", "move", "ctrl+g", "generate", "ctrl+r", "show", "esc", "cancel")
	case scrRaw:
		content = m.viewRaw(w, ch)
		footer = keys("↑↓", "scroll", "esc", "back")
	}

	parts := []string{
		m.header(w),
		"",
		lipgloss.NewStyle().Height(ch).MaxHeight(ch).Render(content),
	}
	if actN > 0 {
		parts = append(parts, "", m.viewActivity(w, actN))
	}
	parts = append(parts, "", m.status(w), lipgloss.NewStyle().MaxWidth(w).Render(footer))
	return lipgloss.NewStyle().Padding(1, 2, 0, 2).Render(strings.Join(parts, "\n"))
}

func (m Model) activityRows() int {
	locked := m.scr != scrMain && m.scr != scrEdit && m.scr != scrRaw && m.scr != scrConfirm && m.scr != scrMembers
	if (!m.activity && !locked) || m.h < 20 {
		return 0
	}
	return max(3, min(8, (m.h-14)/3))
}

func (m Model) header(w int) string {
	name := m.info.Vault
	switch m.scr {
	case scrWelcome:
		name = "welcome"
	case scrCreate:
		name = "new vault"
	case scrJoin, scrPending:
		name = "joining a team"
	}
	left := sAccent.Render("●") + " " + sBold.Render("hush") + sLine.Render("  /  ") + sText.Render(trunc(name, w/2))
	var right string
	if m.svc.Unlocked() {
		right = sCyan.Render("● unlocked") + sMuted.Render(fmt.Sprintf("  %d secrets", len(m.items)))
		if members, err := m.svc.Members(); err == nil {
			if on, others, syncing := online(members); syncing {
				right += sMuted.Render(fmt.Sprintf("  ·  %d/%d online", on, others))
			}
		}
	} else {
		right = sMuted.Render("○ locked")
	}
	gap := max(1, w-lipgloss.Width(left)-lipgloss.Width(right))
	return left + strings.Repeat(" ", gap) + right
}

func (m Model) status(w int) string {
	switch {
	case m.busy != "":
		return m.spin.View() + " " + sMuted.Render(m.busy+"…")
	case m.err != "":
		return sDanger.Render("✕ " + trunc(m.err, w-2))
	case m.note != "":
		return sCyan.Render("✓ ") + sMuted.Render(trunc(m.note, w-2))
	}
	return ""
}

func (m Model) viewActivity(w, n int) string {
	evs := m.svc.Feed().Recent(n)
	lines := []string{rule("activity", w)}
	for range n - len(evs) {
		lines = append(lines, "")
	}
	for i, e := range evs {
		kind := sCyan
		if e.Kind == "deny" {
			kind = sDanger
		}
		msg := sMuted
		if i == len(evs)-1 {
			msg = sText
		}
		lines = append(lines, sFaint.Render(e.At.Format("15:04:05"))+"  "+kind.Render(pad(e.Kind, 7))+" "+msg.Render(trunc(e.Msg, w-18)))
	}
	return strings.Join(lines, "\n")
}

func (m Model) fieldRow(label string, i int, hint string) string {
	marker, ls := "  ", sMuted
	if i == m.focus {
		marker, ls = sAccent.Render("› "), sAccent
	}
	row := marker + ls.Render(pad(label, 12)) + m.fields[i].View()
	if hint != "" && i == m.focus {
		row += "  " + sFaint.Render(hint)
	}
	return row
}

// steps renders a checklist whose items tick off as matching events arrive.
func (m Model) steps(w int, title string, items [][2]string) string {
	seen := map[string]bool{}
	failed := false
	if !m.started.IsZero() {
		for _, e := range m.svc.Feed().Recent(64) {
			if !e.At.Before(m.started) {
				seen[e.Kind] = true
				failed = failed || e.Kind == "deny"
			}
		}
	}
	lines := []string{rule(title, w), ""}
	current := true
	for i, it := range items {
		mark := sFaint.Render(fmt.Sprintf("%02d", i+1))
		style := sMuted
		switch {
		case seen[it[0]]:
			mark, style = sCyan.Render("✓"), sText
		case current && m.busy != "":
			mark, current = m.spin.View(), false
		case current && failed:
			mark, current = sDanger.Render("✕"), false
		}
		lines = append(lines, pad(mark, 2)+"  "+style.Render(trunc(it[1], w-5)))
	}
	return strings.Join(lines, "\n")
}

func (m Model) viewCreate(w int) string {
	dir := shortPath(m.svc.Dir())
	return strings.Join([]string{
		sBold.Render("Create your vault"),
		sMuted.Render(trunc("Stored in "+dir+". Everything happens on this machine; nothing is sent anywhere.", w)),
		"",
		m.fieldRow("vault name", 0, ""),
		m.fieldRow("your name", 1, ""),
		m.fieldRow("passphrase", 2, ""),
		m.fieldRow("confirm", 3, ""),
		"",
		m.steps(w, "what happens when you press enter", [][2]string{
			{"keygen", "generate an ed25519 signing key and an x25519 encryption key"},
			{"kdf", "stretch your passphrase with argon2id (64 MiB, 3 passes)"},
			{"seal", "encrypt your private keys into identity.json (mode 0600)"},
			{"sign", "sign a genesis op: you become the vault's admin"},
			{"wrap", "create a random 256-bit vault key, sealed to your key"},
		}),
	}, "\n")
}

func (m Model) viewUnlock(w int) string {
	return strings.Join([]string{
		sBold.Render(trunc(m.info.Vault, w)),
		sMuted.Render(trunc(fmt.Sprintf("%s  ·  safety number %s", m.info.Me, m.info.Fingerprint), w)),
		sFaint.Render(trunc(fmt.Sprintf("%d secrets · %d ops · key epoch %d · %d member(s)", m.info.Secrets, m.info.Ops, m.info.Epoch, m.info.Members), w)),
		m.adminLine(w),
		"",
		m.fieldRow("passphrase", 0, ""),
		"",
		m.steps(w, "what happens when you press enter", [][2]string{
			{"kdf", "stretch your passphrase with argon2id into a 256-bit key"},
			{"open", "decrypt your private keys from identity.json"},
			{"verify", "check every signature and hash link in ops.jsonl"},
			{"unwrap", "open the vault key that was sealed to you"},
			{"index", "decrypt titles to build the list; passwords stay sealed"},
		}),
	}, "\n")
}

func (m Model) viewMain(w, ch int) string {
	lw := max(22, min(38, w*2/5))
	dw := max(10, w-lw-3)
	sep := sLine.Render(strings.TrimSuffix(strings.Repeat("│\n", ch), "\n"))
	left := lipgloss.NewStyle().Width(lw).Height(ch).Render(m.viewList(lw, ch))
	right := lipgloss.NewStyle().Width(dw).Height(ch).MaxHeight(ch).Render(m.viewDetail(dw))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", sep, " ", right)
}

func (m Model) viewList(lw, ch int) string {
	var rows []string
	if m.searching || m.search.Value() != "" {
		rows = append(rows, m.search.View(), "")
	}
	if len(m.view) == 0 {
		if m.search.Value() != "" {
			rows = append(rows, sMuted.Render("no matches"))
		} else {
			rows = append(rows, sMuted.Render("empty"))
		}
		return strings.Join(rows, "\n")
	}
	avail := max(1, ch-len(rows))
	top := 0
	if m.cursor >= avail {
		top = m.cursor - avail + 1
	}
	for i := top; i < len(m.view) && i < top+avail; i++ {
		it := m.view[i]
		marker, ts := "  ", sText
		if i == m.cursor {
			marker, ts = sAccent.Render("▍ "), sBold
		}
		title := trunc(it.Title, lw-2)
		if len(it.Exposed) > 0 {
			title = trunc(it.Title, lw-4)
		}
		line := marker + ts.Render(title)
		if len(it.Exposed) > 0 {
			line += sDanger.Render(" !")
			title += " !"
		}
		if room := lw - 2 - lipgloss.Width(title) - 2; it.Username != "" && room >= 4 {
			user := trunc(it.Username, room)
			line += strings.Repeat(" ", lw-2-lipgloss.Width(title)-lipgloss.Width(user)) + sFaint.Render(user)
		}
		rows = append(rows, line)
	}
	return strings.Join(rows, "\n")
}

func (m Model) viewDetail(dw int) string {
	it := m.selected()
	if it == nil {
		if m.search.Value() != "" {
			return sMuted.Render("Nothing matches that search.")
		}
		return strings.Join([]string{
			sBold.Render("Nothing here yet"),
			sMuted.Render("Press n to add your first secret."),
			"",
			sFaint.Render(trunc("Secrets are encrypted with xchacha20-poly1305", dw)),
			sFaint.Render(trunc("before anything is written to disk.", dw)),
		}, "\n")
	}

	row := func(label, value string) string {
		return sMuted.Render(pad(label, 11)) + value
	}
	sealed := sFaint.Render("sealed · enter to decrypt")
	vw := max(4, dw-11)

	lines := []string{
		sBold.Render(trunc(it.Title, dw)),
		sFaint.Render(trunc(fmt.Sprintf("v%d · updated %s by %s", it.Version, ago(it.Updated), it.Author), dw)),
		"",
	}
	if len(it.Exposed) > 0 {
		lines = append(lines,
			sDanger.Render(trunc("! "+strings.Join(it.Exposed, ", ")+" could read this value before removal", dw)),
			sFaint.Render(trunc("  change it at the source, then edit and save here", dw)),
			"")
	}
	lines = append(lines,
		row("username", sText.Render(trunc(it.Username, vw))))
	if m.open != nil {
		pw := sText.Render(strings.Repeat("•", min(16, len([]rune(m.open.Password)))))
		if m.showPass {
			pw = sAccent.Render(trunc(m.open.Password, vw))
		}
		lines = append(lines, row("password", pw), row("url", sText.Render(trunc(it.URL, vw))))
		notes := strings.Split(lipgloss.NewStyle().Width(vw).Render(m.open.Notes), "\n")
		for i, n := range notes {
			label := ""
			if i == 0 {
				label = "notes"
			}
			lines = append(lines, row(label, sText.Render(n)))
		}
	} else {
		lines = append(lines, row("password", sealed), row("url", sText.Render(trunc(it.URL, vw))), row("notes", sealed))
	}

	lines = append(lines, "",
		rule("under the hood", dw),
		row("stored as", sFaint.Render(trunc("secret.put op "+it.Op, vw))),
		row("cipher", sFaint.Render(trunc(fmt.Sprintf("xchacha20-poly1305 · epoch %d key", it.Epoch), vw))),
		row("size", sFaint.Render(fmt.Sprintf("%d B ciphertext", it.Size))),
		row("in memory", sFaint.Render(trunc(memState(m.open != nil), vw))),
		"",
	)
	if m.scr == scrConfirm {
		lines = append(lines, sDanger.Render(trunc(fmt.Sprintf("Delete %q?", it.Title), dw)),
			sFaint.Render(trunc("It disappears for everyone; old encrypted versions stay in the log.", dw)))
	} else {
		lines = append(lines, keys("enter", "open", "p", "show", "c", "copy"),
			keys("u", "copy user", "e", "edit", "d", "delete", "x", "on disk"))
	}
	return strings.Join(lines, "\n")
}

func memState(open bool) string {
	if open {
		return "decrypted until you move away"
	}
	return "only title, username and url"
}

func (m Model) viewEdit(w int) string {
	title := "New secret"
	if m.editID != "" {
		title = "Edit secret"
	}
	return strings.Join([]string{
		sBold.Render(title),
		sMuted.Render("Nothing is written until you press ctrl+s."),
		"",
		m.fieldRow("title", 0, ""),
		m.fieldRow("username", 1, ""),
		m.fieldRow("password", 2, "ctrl+g generate · ctrl+r show"),
		m.fieldRow("url", 3, ""),
		m.fieldRow("notes", 4, ""),
		"",
		rule("what happens when you save", w),
		"",
		sAccent.Render("01") + "  " + sMuted.Render(clip("your fields become json, in memory only", w-4)),
		sAccent.Render("02") + "  " + sMuted.Render(clip(fmt.Sprintf("encrypted with the epoch %d vault key · xchacha20-poly1305 · fresh nonce", m.info.Epoch), w-4)),
		sAccent.Render("03") + "  " + sMuted.Render(clip("wrapped in a secret.put op and signed with your ed25519 key", w-4)),
		sAccent.Render("04") + "  " + sMuted.Render(clip("appended to ops.jsonl and fsynced; plaintext never touches disk", w-4)),
	}, "\n")
}

func (m Model) viewRaw(w, ch int) string {
	head := []string{
		sBold.Render("On disk") + sMuted.Render(clip("  ·  the exact op ops.jsonl holds for this secret", w-8)),
		sFaint.Render(trunc("Only ct is secret, and it is ciphertext. id = sha-256 of the op, sig = ed25519 by author.", w)),
		"",
	}
	avail := max(1, ch-len(head))
	end := min(len(m.raw), m.rawTop+avail)
	for _, line := range m.raw[m.rawTop:end] {
		line = clip(line, w)
		if i := strings.Index(line, `": `); i > 0 && strings.HasPrefix(strings.TrimSpace(line), `"`) {
			head = append(head, sCyan.Render(line[:i+1])+sMuted.Render(":")+sText.Render(line[i+2:]))
		} else {
			head = append(head, sMuted.Render(line))
		}
	}
	return strings.Join(head, "\n")
}
