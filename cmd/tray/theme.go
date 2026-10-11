package main

import (
	"image"
	"image/color"
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

var (
	colorIconGray  = color.RGBA{R: 0x9a, G: 0x9a, B: 0x9a, A: 0xff}
	colorIconGreen = color.RGBA{R: 0x2e, G: 0xa0, B: 0x4e, A: 0xff}
	colorIconRed   = color.RGBA{R: 0xc0, G: 0x39, B: 0x2b, A: 0xff}

	iconGray, iconGreen, iconRed *walk.Icon

	// dark theme colors
	darkWindowBg = walk.RGB(0x1e, 0x1e, 0x1e)
	darkPanelBg  = walk.RGB(0x25, 0x25, 0x26)
	darkText     = walk.RGB(0xe0, 0xe0, 0xe0)
)

// applyDarkTheme makes the title bar and controls dark. These APIs are
// undocumented but Notepad++ and others use them too.
func applyDarkTheme() {
	setDarkTitleBar(mainWin.Handle())
	for _, h := range []win.HWND{
		connList.Handle(), nameEdit.Handle(), vpnAddrEdit.Handle(),
		clientKeyEdit.Handle(), gameProcEdit.Handle(),
		connectBtn.Handle(), disconnectBtn.Handle(), pingBtn.Handle(),
	} {
		setDarkControlTheme(h)
	}
}

func setDarkTitleBar(hwnd win.HWND) {
	dwmapi := syscall.NewLazyDLL("dwmapi.dll")
	proc := dwmapi.NewProc("DwmSetWindowAttribute")
	const dwmwaUseImmersiveDarkMode = 20 // Windows 10 1903+ / 11
	v := int32(1)
	_, _, _ = proc.Call(uintptr(hwnd), dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
}

func setDarkControlTheme(hwnd win.HWND) {
	uxtheme := syscall.NewLazyDLL("uxtheme.dll")
	proc := uxtheme.NewProc("SetWindowTheme")
	name, err := syscall.UTF16PtrFromString("DarkMode_Explorer")
	if err != nil {
		return
	}
	_, _, _ = proc.Call(uintptr(hwnd), uintptr(unsafe.Pointer(name)), 0)
}

// solidIcon draws a colored circle, so we don't need .ico files.
func solidIcon(c color.RGBA) (*walk.Icon, error) {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	cx, cy := float64(size)/2, float64(size)/2
	r := float64(size)/2 - 2
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			if dx*dx+dy*dy <= r*r {
				img.Set(x, y, c)
			}
		}
	}
	return walk.NewIconFromImage(img)
}
