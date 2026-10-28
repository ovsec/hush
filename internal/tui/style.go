package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// One accent, one secondary, and greys. Adaptive for light and dark terminals.
var (
	cAccent = lipgloss.AdaptiveColor{Light: "#C2185B", Dark: "#F38BA8"}
	cCyan   = lipgloss.AdaptiveColor{Light: "#00838F", Dark: "#89DCEB"}
	cText   = lipgloss.AdaptiveColor{Light: "#24292F", Dark: "#E6E6E6"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#6E7781", Dark: "#8B8B8B"}
	cFaint  = lipgloss.AdaptiveColor{Light: "#AFB8C1", Dark: "#4A4A4A"}
	cDanger = lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#FF7B72"}
)

var (
	sText   = lipgloss.NewStyle().Foreground(cText)
	sBold   = lipgloss.NewStyle().Foreground(cText).Bold(true)
	sMuted  = lipgloss.NewStyle().Foreground(cMuted)
	sFaint  = lipgloss.NewStyle().Foreground(cFaint)
	sAccent = lipgloss.NewStyle().Foreground(cAccent)
	sBrand  = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sCyan   = lipgloss.NewStyle().Foreground(cCyan)
	sDanger = lipgloss.NewStyle().Foreground(cDanger)
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

func rule(label string, w int) string {
	l := sMuted.Render(label) + " "
	return l + sFaint.Render(strings.Repeat("─", max(0, w-lipgloss.Width(l))))
}

func keys(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, sText.Render(pairs[i])+" "+sMuted.Render(pairs[i+1]))
	}
	return strings.Join(parts, sFaint.Render("  ·  "))
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
