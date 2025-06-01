@echo off
chcp 65001 >nul
echo ====================================================================
echo Cat Message v2.0 一体化编译脚本 (Windows)
echo AES+RSA2048混合加密版本
echo ====================================================================
echo.

:: 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 错误: Python未安装或未添加到PATH
    echo 请先安装Python 3.8或更高版本
    pause
    exit /b 1
)

echo ✅ Python环境检查通过
echo.

:: 检查并安装依赖
echo 📦 检查依赖包...
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo 正在安装PyInstaller...
    pip install pyinstaller
)

pip show pycryptodome >nul 2>&1
if errorlevel 1 (
    echo 正在安装PyCryptodome...
    pip install pycryptodome
)

pip show PyQt6 >nul 2>&1
if errorlevel 1 (
    echo 正在安装PyQt6...
    pip install PyQt6
)

pip show requests >nul 2>&1
if errorlevel 1 (
    echo 正在安装requests...
    pip install requests
)

echo ✅ 依赖包检查完成
echo.

:: 创建输出目录
set BUILD_DIR=build_output
set WIN_DIR=%BUILD_DIR%\windows
set LINUX_DIR=%BUILD_DIR%\linux

if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
mkdir %BUILD_DIR%
mkdir %WIN_DIR%
mkdir %LINUX_DIR%

echo 🏗️  开始编译Windows版本...
echo.

:: 编译Windows服务端
echo 📡 编译服务端 (Windows)...
pyinstaller --onefile ^
    --name cat-message-server-win ^
    --distpath %WIN_DIR% ^
    --workpath build_temp ^
    --specpath build_specs ^
    --add-data "config.ini;." ^
    --hidden-import=Crypto.Cipher.AES ^
    --hidden-import=Crypto.Cipher.PKCS1_OAEP ^
    --hidden-import=Crypto.PublicKey.RSA ^
    --hidden-import=Crypto.Random ^
    --hidden-import=Crypto.Util.Padding ^
    --console ^
    src/server.py

if errorlevel 1 (
    echo ❌ 服务端编译失败
    pause
    exit /b 1
)

echo ✅ 服务端编译完成

:: 编译Windows客户端
echo 🖥️  编译客户端 (Windows)...
pyinstaller --onefile ^
    --name cat-message-client-win ^
    --distpath %WIN_DIR% ^
    --workpath build_temp ^
    --specpath build_specs ^
    --hidden-import=Crypto.Cipher.AES ^
    --hidden-import=Crypto.Cipher.PKCS1_OAEP ^
    --hidden-import=Crypto.PublicKey.RSA ^
    --hidden-import=Crypto.Random ^
    --hidden-import=Crypto.Util.Padding ^
    --windowed ^
    src/user.py

if errorlevel 1 (
    echo ❌ 客户端编译失败
    pause
    exit /b 1
)

echo ✅ 客户端编译完成
echo.

:: 创建Windows发布包
echo 📦 创建Windows发布包...

:: 复制配置文件和文档
copy config.ini %WIN_DIR%\ >nul 2>&1
copy README.md %WIN_DIR%\ >nul 2>&1

:: 创建启动脚本
echo @echo off > %WIN_DIR%\start_server.bat
echo echo 正在启动 Cat Message 服务器... >> %WIN_DIR%\start_server.bat
echo echo 按 Ctrl+C 停止服务器 >> %WIN_DIR%\start_server.bat
echo echo. >> %WIN_DIR%\start_server.bat
echo cat-message-server-win.exe >> %WIN_DIR%\start_server.bat
echo pause >> %WIN_DIR%\start_server.bat

echo @echo off > %WIN_DIR%\start_client.bat
echo echo 正在启动 Cat Message 客户端... >> %WIN_DIR%\start_client.bat
echo cat-message-client-win.exe >> %WIN_DIR%\start_client.bat

:: 创建说明文件
echo Cat Message v2.0 Windows版 > %WIN_DIR%\README_Windows.txt
echo AES+RSA2048混合加密版本 >> %WIN_DIR%\README_Windows.txt
echo. >> %WIN_DIR%\README_Windows.txt
echo 使用说明： >> %WIN_DIR%\README_Windows.txt
echo 1. 服务端：双击 start_server.bat 启动服务器 >> %WIN_DIR%\README_Windows.txt
echo 2. 客户端：双击 start_client.bat 启动客户端 >> %WIN_DIR%\README_Windows.txt
echo 3. 或者直接运行对应的.exe文件 >> %WIN_DIR%\README_Windows.txt
echo. >> %WIN_DIR%\README_Windows.txt
echo 端口说明： >> %WIN_DIR%\README_Windows.txt
echo - 12345: 聊天服务端口 >> %WIN_DIR%\README_Windows.txt
echo - 12346: 文件/图片服务端口 >> %WIN_DIR%\README_Windows.txt
echo. >> %WIN_DIR%\README_Windows.txt
echo 配置文件：config.ini >> %WIN_DIR%\README_Windows.txt
echo 加密模式：AES+RSA2048混合加密 >> %WIN_DIR%\README_Windows.txt

echo ✅ Windows版本编译完成！
echo 📁 输出目录: %WIN_DIR%
echo.

:: 检查是否在Linux环境中运行（通过WSL或双启动）
echo 🐧 检查Linux编译环境...

:: 尝试检测WSL
wsl --version >nul 2>&1
if not errorlevel 1 (
    echo ✅ 检测到WSL环境，开始编译Linux版本...
    call :build_linux_wsl
) else (
    echo ⚠️  未检测到WSL环境
    echo 💡 Linux版本编译需要以下环境之一：
    echo    1. WSL (Windows Subsystem for Linux)
    echo    2. 在Linux系统中运行对应的build_all.sh脚本
    echo    3. 使用Docker容器编译
    echo.
    echo 📝 已创建Linux编译脚本: build_all_linux.sh
    call :create_linux_script
)

echo.
echo ====================================================================
echo 🎉 编译完成！
echo.
echo 📁 输出目录:
echo    Windows版本: %WIN_DIR%
if exist %LINUX_DIR%\cat-message-server-linux (
    echo    Linux版本:   %LINUX_DIR%
)
echo.
echo 📋 文件列表:
dir /b %WIN_DIR%
echo.
echo ✨ 享受使用 Cat Message v2.0！
echo ====================================================================
pause
exit /b 0

:build_linux_wsl
echo.
echo 🐧 在WSL中编译Linux版本...

:: 创建WSL编译脚本
echo #!/bin/bash > wsl_build.sh
echo echo "=== Cat Message Linux编译 (通过WSL) ===" >> wsl_build.sh
echo cd /mnt/c%CD:\=/%/ >> wsl_build.sh
echo echo "安装Python依赖..." >> wsl_build.sh
echo pip3 install pyinstaller pycryptodome requests >/dev/null 2>&1 >> wsl_build.sh
echo echo "编译服务端..." >> wsl_build.sh
echo pyinstaller --onefile --name cat-message-server-linux --distpath build_output/linux --console src/server.py >> wsl_build.sh
echo echo "编译客户端..." >> wsl_build.sh
echo pyinstaller --onefile --name cat-message-client-linux --distpath build_output/linux --console src/user.py >> wsl_build.sh
echo echo "创建启动脚本..." >> wsl_build.sh
echo echo "#!/bin/bash" ^> build_output/linux/start_server.sh >> wsl_build.sh
echo echo "echo '正在启动 Cat Message 服务器...'" ^>^> build_output/linux/start_server.sh >> wsl_build.sh
echo echo "./cat-message-server-linux" ^>^> build_output/linux/start_server.sh >> wsl_build.sh
echo chmod +x build_output/linux/start_server.sh >> wsl_build.sh
echo echo "#!/bin/bash" ^> build_output/linux/start_client.sh >> wsl_build.sh
echo echo "echo '正在启动 Cat Message 客户端...'" ^>^> build_output/linux/start_client.sh >> wsl_build.sh
echo echo "./cat-message-client-linux" ^>^> build_output/linux/start_client.sh >> wsl_build.sh
echo chmod +x build_output/linux/start_client.sh >> wsl_build.sh
echo chmod +x build_output/linux/cat-message-* >> wsl_build.sh
echo cp config.ini build_output/linux/ 2>/dev/null >> wsl_build.sh
echo echo "Linux版本编译完成！" >> wsl_build.sh

wsl bash wsl_build.sh
del wsl_build.sh

if exist %LINUX_DIR%\cat-message-server-linux (
    echo ✅ Linux版本编译成功！
) else (
    echo ⚠️  Linux版本编译可能失败，请检查WSL环境
)
exit /b 0

:create_linux_script
echo #!/bin/bash > build_all_linux.sh
echo echo "====================================================================" >> build_all_linux.sh
echo echo "Cat Message v2.0 一体化编译脚本 (Linux)" >> build_all_linux.sh
echo echo "AES+RSA2048混合加密版本" >> build_all_linux.sh
echo echo "====================================================================" >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo # 检查Python >> build_all_linux.sh
echo if ! command -v python3 ^&^>/dev/null; then >> build_all_linux.sh
echo     echo "❌ 错误: Python3未安装" >> build_all_linux.sh
echo     echo "请运行: sudo apt update && sudo apt install python3 python3-pip" >> build_all_linux.sh
echo     exit 1 >> build_all_linux.sh
echo fi >> build_all_linux.sh
echo echo "✅ Python环境检查通过" >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo # 安装依赖 >> build_all_linux.sh
echo echo "📦 安装依赖包..." >> build_all_linux.sh
echo pip3 install pyinstaller pycryptodome requests >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo # 创建输出目录 >> build_all_linux.sh
echo BUILD_DIR="build_output/linux" >> build_all_linux.sh
echo rm -rf $BUILD_DIR >> build_all_linux.sh
echo mkdir -p $BUILD_DIR >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo # 编译服务端 >> build_all_linux.sh
echo echo "📡 编译服务端 (Linux)..." >> build_all_linux.sh
echo pyinstaller --onefile --name cat-message-server-linux --distpath $BUILD_DIR --console src/server.py >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo # 编译客户端 >> build_all_linux.sh
echo echo "🖥️  编译客户端 (Linux)..." >> build_all_linux.sh
echo pyinstaller --onefile --name cat-message-client-linux --distpath $BUILD_DIR --console src/user.py >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo # 创建启动脚本 >> build_all_linux.sh
echo echo "📦 创建启动脚本..." >> build_all_linux.sh
echo cat ^> $BUILD_DIR/start_server.sh ^<^< 'EOF' >> build_all_linux.sh
echo #!/bin/bash >> build_all_linux.sh
echo cd "$(dirname "$0")" >> build_all_linux.sh
echo echo "正在启动 Cat Message 服务器..." >> build_all_linux.sh
echo ./cat-message-server-linux >> build_all_linux.sh
echo EOF >> build_all_linux.sh
echo cat ^> $BUILD_DIR/start_client.sh ^<^< 'EOF' >> build_all_linux.sh
echo #!/bin/bash >> build_all_linux.sh
echo cd "$(dirname "$0")" >> build_all_linux.sh
echo echo "正在启动 Cat Message 客户端..." >> build_all_linux.sh
echo ./cat-message-client-linux >> build_all_linux.sh
echo EOF >> build_all_linux.sh
echo chmod +x $BUILD_DIR/*.sh >> build_all_linux.sh
echo chmod +x $BUILD_DIR/cat-message-* >> build_all_linux.sh
echo cp config.ini $BUILD_DIR/ 2>/dev/null >> build_all_linux.sh
echo echo >> build_all_linux.sh
echo echo "✅ Linux版本编译完成！" >> build_all_linux.sh
echo echo "📁 输出目录: $BUILD_DIR" >> build_all_linux.sh

echo ✅ 已创建Linux编译脚本: build_all_linux.sh
echo 💡 在Linux系统中运行: chmod +x build_all_linux.sh && ./build_all_linux.sh
exit /b 0 