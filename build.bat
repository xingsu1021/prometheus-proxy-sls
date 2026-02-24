@echo off
set GOROOT=C:\Program Files\Go
set PATH=%GOROOT%\bin;%PATH%
go version
go build -o prometheus-remoteread-sls.exe .
