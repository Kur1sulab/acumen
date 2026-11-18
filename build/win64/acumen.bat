@echo off
setlocal
cd /d "%~dp0"

rem 控制台走 GBK，和代码里的中文输出对齐；Python 也固定用 GBK 写 stdout
set "PYTHONIOENCODING=gbk"
set "PYTHONDONTWRITEBYTECODE=1"

if not exist "python\python.exe" goto :nopython

echo.
echo   鉴微 Acumen  v1.1.0
echo   ---------------------------------------------
echo   本机看板 · 只在 127.0.0.1 上监听 · 不联网
echo.
echo   启动后浏览器会自动打开；关闭这个窗口即停止服务。
echo.
echo   想换端口：acumen.bat --port 7799
echo.

"python\python.exe" -m vc.server --port 7788 --open %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" goto :crashed
echo.
echo   [acumen] 已停止。
timeout /t 3 >nul 2>&1
goto :eof

:crashed
echo.
echo   [异常退出] 退出码 %RC%
echo.
pause
goto :eof

:nopython
echo.
echo   [错误] 找不到 python\python.exe —— 这个包不完整。
echo   请确认整个压缩包完整解压后再双击本文件。
echo.
pause
