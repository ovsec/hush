package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// minimal-tech: ink, muted, line-strong, line; one rose accent for human
// decisions and cyan only for system signals. Adaptive for light and dark.
var (
	cAccent = lipgloss.AdaptiveColor{Light: "#E11D48", Dark: "#FB7185"}
	cCyan   = lipgloss.AdaptiveColor{Light: "#0D9488", Dark: "#2DD4BF"}
	cText   = lipgloss.AdaptiveColor{Light: "#18181B", Dark: "#F4F4F8"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#5F5F6B", Dark: "#A1A1B5"}
	cFaint  = lipgloss.AdaptiveColor{Light: "#8B8B8D", Dark: "#838386"}
	cLine   = lipgloss.AdaptiveColor{Light: "#D1D1D3", Dark: "#3B3B3E"}
	cDanger = cAccent // warnings are human decisions: same rose
)

var (
	sText    = lipgloss.NewStyle().Foreground(cText)
	sBold    = lipgloss.NewStyle().Foreground(cText).Bold(true)
	sMuted   = lipgloss.NewStyle().Foreground(cMuted)
	sFaint   = lipgloss.NewStyle().Foreground(cFaint)
	sLine    = lipgloss.NewStyle().Foreground(cLine)
	sEyebrow = lipgloss.NewStyle().Foreground(cMuted).Bold(true)
	sAccent  = lipgloss.NewStyle().Foreground(cAccent)
	sBrand   = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sCyan    = lipgloss.NewStyle().Foreground(cCyan)
	sDanger  = lipgloss.NewStyle().Foreground(cDanger)
)

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if n <= 0 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// clip shortens s to n runes without touching its whitespace.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 1 {
		return s
	}
	return string(r[:n-1]) + "…"
}

func pad(s string, w int) string {
	if gap := w - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}

// rule is a section eyebrow: UPPERCASE, then a hairline.
func rule(label string, w int) string {
	l := sEyebrow.Render(strings.ToUpper(label)) + "  "
	return l + sLine.Render(strings.Repeat("─", max(0, w-lipgloss.Width(l))))
}

func keys(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, sText.Render(pairs[i])+" "+sMuted.Render(pairs[i+1]))
	}
	return strings.Join(parts, sLine.Render("  ·  "))
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.Format("2 Jan 2006")
}
