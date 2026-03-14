#Requires AutoHotkey v2.0
#SingleInstance Force

; ----------------------------
; Helper: type text into active window
; ----------------------------
TypeCmd(text) {
    SendText text
}

CapsLock & v:: { ; CapsLock+v hotkey to start typing clipboard contents
    ClipText := A_Clipboard ; Store clipboard contents into a variable

    ; Parse clipboard content character by character
    for char in StrSplit(ClipText, "") {
        SendText char ; Send each character as raw input
        Sleep 20 ; Optional delay between characters
    }
}

; Disable the default Caps Lock behavior
SetCapsLockState "AlwaysOff"

; --- WASD NAVIGATION (Hold Caps Lock + W/A/S/D) ---
CapsLock & w::Send("{Up}")
CapsLock & a::Send("{Left}")
CapsLock & s::Send("{Down}")
CapsLock & d::Send("{Right}")

; --- CONVENIENCE NAV ---
CapsLock & q::Send("^{Left}")  ; Jump back one word
CapsLock & e::Send("^{Right}") ; Jump forward one word

; --- CCDC COMMAND TYPERS (typed into VM, not run locally) ---
CapsLock & 1::TypeCmd('whoami /all')
CapsLock & 2::TypeCmd('hostname && ipconfig /all')
CapsLock & 3::TypeCmd('net user && net localgroup administrators')
CapsLock & 4::TypeCmd('quser')
CapsLock & 5::TypeCmd('tasklist /svc')
CapsLock & 6::TypeCmd('netstat -ano')
CapsLock & 7::TypeCmd('sc query type= service state= all')
CapsLock & 8::TypeCmd('schtasks /query /fo LIST /v')
CapsLock & 9::TypeCmd('powershell -NoProfile -Command "Get-LocalUser | Select Name,Enabled,LastLogon"')
