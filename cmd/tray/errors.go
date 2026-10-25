package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/lxn/walk"
)

// Why client.exe stopped, taken from its last log lines, so the tray can
// say more than "exited unexpectedly".
type clientErrKind int32

const (
	errNone clientErrKind = iota
	errPinMismatch
	errKeyRejected
)

var lastClientErr atomic.Int32

// noteClientLine looks for the fatal errors client.exe prints (see
// transport.ErrPinMismatch and auth.ErrRejected).
func noteClientLine(s string) {
	switch {
	case strings.Contains(s, "server certificate does not match pinned fingerprint"):
		lastClientErr.Store(int32(errPinMismatch))
	case strings.Contains(s, "server rejected the client key"):
		lastClientErr.Store(int32(errKeyRejected))
	}
}

// reportClientExit shows why client.exe stopped on its own.
func reportClientExit() {
	switch clientErrKind(lastClientErr.Load()) {
	case errPinMismatch:
		fail("сертификат сервера изменился")
		askResetPin()
	case errKeyRejected:
		fail("сервер не принял ключ: его нет в authorized_keys.json на сервере")
	default:
		fail("клиент неожиданно завершился, смотри tray.log")
	}
}

// askResetPin explains a changed server certificate. With pin_file the
// user can drop the saved fingerprint; a new one is saved on the next
// connect. That's only right if the certificate was really regenerated
// on the server, so the question says what else it can mean.
func askResetPin() {
	serverPin, pinPath := pinConfig()
	ui(func() {
		if serverPin != "" {
			walk.MsgBox(mainWin, "splicertc",
				"Сертификат сервера не совпадает с server_pin в client-config.json.\n\n"+
					"Если сертификат на сервере пересоздавали, впиши новый отпечаток из лога сервера "+
					"(строка \"cert fingerprint\").\n\n"+
					"Если на сервере ничего не меняли, кто-то может перехватывать соединение.",
				walk.MsgBoxOK|walk.MsgBoxIconWarning)
			return
		}
		if pinPath == "" {
			return
		}
		answer := walk.MsgBox(mainWin, "splicertc",
			"Сертификат сервера изменился и не совпадает с сохранённым.\n\n"+
				"Если сертификат на сервере пересоздавали (gencert, переустановка), нажми «Да»: "+
				"сохранённый отпечаток удалится, а при следующем подключении запомнится новый.\n\n"+
				"Если на сервере ничего не меняли, нажми «Нет»: возможно, кто-то перехватывает соединение.",
			walk.MsgBoxYesNo|walk.MsgBoxIconWarning)
		if answer != walk.DlgCmdYes {
			return
		}
		if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
			setStatus("не удалось удалить " + filepath.Base(pinPath) + ": " + err.Error())
			return
		}
		logger.Println("pin file removed by the user:", pinPath)
		setStatus("отпечаток сброшен, можно подключаться")
	})
}
