package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Header / chrome
	styleHeader    = lipgloss.NewStyle().Bold(true)
	styleDim       = lipgloss.NewStyle().Faint(true)
	styleAccent    = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true) // blue
	styleBar       = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))            // green
	styleBarTrail  = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))           // dark gray
	styleSep       = lipgloss.NewStyle().Faint(true)
	styleHelp      = lipgloss.NewStyle().Faint(true)
	styleFilterBox = lipgloss.NewStyle().Foreground(lipgloss.Color("11")) // yellow

	// Table header
	styleColHeader = lipgloss.NewStyle().Bold(true).Faint(true)

	// Row states
	styleOpen    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))  // green
	styleBanner  = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))  // cyan
	styleTimeout = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))   // dark gray
	styleService = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))  // magenta
	styleBanTxt  = lipgloss.NewStyle().Foreground(lipgloss.Color("250")) // light gray

	// Selection
	styleCursor    = lipgloss.NewStyle().Background(lipgloss.Color("236")).Bold(true) // subtle bg
	styleCursorDim = lipgloss.NewStyle().Background(lipgloss.Color("236")).Faint(true)

	// Detail pane
	styleDetailBorder = lipgloss.NewStyle().Faint(true)
	styleDetailText   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	// Filter tabs
	styleTabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("10"))
	styleTabInactive = lipgloss.NewStyle().Faint(true)

	// Service view
	styleServiceCat = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true) // blue: category
	styleHostRef    = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Faint(true)
)
