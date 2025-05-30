#!/bin/bash

# Cat Message 服务器 Linux 一体包构建脚本
# Build script for Cat Message Server Linux standalone package

echo "===================================="
echo "Cat Message 服务器 Linux 构建工具"
echo "===================================="

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到Python3，请先安装Python3"
    exit 1
fi

# 检查pip是否安装
if ! command -v pip3 &> /dev/null; then
    echo "错误: 未找到pip3，请先安装pip3"
    exit 1
fi

echo "正在检查/安装依赖..."

# 安装PyInstaller（如果没有安装）
if ! pip3 show pyinstaller &> /dev/null; then
    echo "正在安装PyInstaller..."
    pip3 install pyinstaller
fi

# 安装项目依赖
echo "正在安装项目依赖..."
pip3 install -r requirements.txt

# 检查src/server.py是否存在
if [ ! -f "src/server.py" ]; then
    echo "错误: 未找到src/server.py文件"
    exit 1
fi

# 检查并创建完整的config.ini文件
echo "正在检查配置文件..."
if [ ! -f "config.ini" ]; then
    echo "创建默认config.ini文件..."
    cat > config.ini << 'CONFIGEOF'
[server]
port = 12345

[file_settings]
enable_file_limit = false
max_file_size_mb = 100
CONFIGEOF
else
    # 检查config.ini是否包含必要的sections
    if ! grep -q "\[server\]" config.ini; then
        echo "更新config.ini文件，添加[server]部分..."
        echo "" >> config.ini
        echo "[server]" >> config.ini
        echo "port = 12345" >> config.ini
    fi
    
    if ! grep -q "\[file_settings\]" config.ini; then
        echo "更新config.ini文件，添加[file_settings]部分..."
        echo "" >> config.ini
        echo "[file_settings]" >> config.ini
        echo "enable_file_limit = false" >> config.ini
        echo "max_file_size_mb = 100" >> config.ini
    fi
fi

echo "开始构建服务器..."

# 创建Linux专用的spec文件
cat > server_linux.spec << 'EOF'
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/server.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.ini', '.'),
    ],
    hiddenimports=[
        'Crypto.PublicKey.RSA',
        'Crypto.Cipher.PKCS1_OAEP',
        'configparser',
        'threading',
        'http.server',
        'socketserver',
        'uuid',
        'os',
        'json',
        'base64',
        'logging'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cat-message-server-linux',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
EOF

# 使用PyInstaller构建
echo "正在使用PyInstaller构建..."
pyinstaller --clean server_linux.spec

# 检查构建结果
if [ -f "dist/cat-message-server-linux" ]; then
    echo ""
    echo "🎉 构建成功！"
    echo "可执行文件位置: dist/cat-message-server-linux"
    echo ""
    
    # 创建发布目录
    echo "正在创建发布包..."
    RELEASE_DIR="cat-message-server-linux-$(date +%Y%m%d)"
    mkdir -p "$RELEASE_DIR"
    
    # 复制可执行文件
    cp "dist/cat-message-server-linux" "$RELEASE_DIR/"
    
    # 复制配置文件
    if [ -f "config.ini" ]; then
        cp "config.ini" "$RELEASE_DIR/"
    else
        # 创建默认配置文件
        cat > "$RELEASE_DIR/config.ini" << 'CONFIGEOF'
[server]
port = 12345

[file_settings]
enable_file_limit = false
max_file_size_mb = 100
CONFIGEOF
    fi
    
    # 创建目录结构
    mkdir -p "$RELEASE_DIR/file_storage"
    mkdir -p "$RELEASE_DIR/image_storage"
    mkdir -p "$RELEASE_DIR/logs"
    
    # 创建启动脚本
    cat > "$RELEASE_DIR/start.sh" << 'STARTEOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "正在启动 Cat Message 服务器..."
echo "按 Ctrl+C 停止服务器"
echo ""
./cat-message-server-linux
STARTEOF
    chmod +x "$RELEASE_DIR/start.sh"
    
    # 创建后台运行脚本
    cat > "$RELEASE_DIR/start_daemon.sh" << 'DAEMONEOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "正在后台启动 Cat Message 服务器..."
nohup ./cat-message-server-linux > logs/server.log 2>&1 &
SERVER_PID=$!
echo "服务器已启动，PID: $SERVER_PID"
echo "日志文件: logs/server.log"
echo "要停止服务器，请运行: kill $SERVER_PID"
echo "$SERVER_PID" > server.pid
DAEMONEOF
    chmod +x "$RELEASE_DIR/start_daemon.sh"
    
    # 创建停止脚本
    cat > "$RELEASE_DIR/stop.sh" << 'STOPEOF'
#!/bin/bash
cd "$(dirname "$0")"
if [ -f "server.pid" ]; then
    PID=$(cat server.pid)
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        echo "服务器已停止 (PID: $PID)"
        rm server.pid
    else
        echo "服务器进程不存在 (PID: $PID)"
        rm server.pid
    fi
else
    echo "未找到服务器PID文件"
    echo "尝试查找并停止所有cat-message-server-linux进程..."
    pkill cat-message-server-linux
fi
STOPEOF
    chmod +x "$RELEASE_DIR/stop.sh"
    
    # 创建说明文件
    cat > "$RELEASE_DIR/README.txt" << 'READMEEOF'
Cat Message 服务器 Linux 版
===========================

运行方法:

1. 前台运行 (推荐测试时使用):
   双击 start.sh 或在终端运行: ./start.sh
   
2. 后台运行 (推荐生产环境):
   ./start_daemon.sh
   
3. 停止服务器:
   ./stop.sh

配置文件:
- config.ini: 服务器配置
  - [server] port: 服务器端口 (默认12345)
  - [file_settings]: 文件上传限制设置

目录说明:
- file_storage/: 用户上传的文件存储
- image_storage/: 图片文件存储  
- logs/: 日志文件存储

服务器功能:
- 支持多客户端连接
- 支持RSA加密通信 (无加密/RSA2048/RSA4096/RSA8192)
- 支持文件和图片传输
- HTTP文件下载服务 (端口12346)
- 聊天记录存储

网络端口:
- 12345: 主要聊天服务器端口
- 12346: HTTP文件下载服务端口

防火墙设置:
如需外部访问，请开放相应端口:
sudo ufw allow 12345
sudo ufw allow 12346

构建时间: $(date)
READMEEOF
    
    # 设置可执行权限
    chmod +x "$RELEASE_DIR/cat-message-server-linux"
    
    # 创建tar.gz压缩包
    tar -czf "${RELEASE_DIR}.tar.gz" "$RELEASE_DIR"
    
    echo "📦 发布包已创建:"
    echo "  目录: $RELEASE_DIR/"
    echo "  压缩包: ${RELEASE_DIR}.tar.gz"
    echo ""
    echo "文件大小:"
    ls -lh "$RELEASE_DIR/cat-message-server-linux"
    ls -lh "${RELEASE_DIR}.tar.gz"
    
    echo ""
    echo "📁 发布包内容:"
    ls -la "$RELEASE_DIR/"
    
else
    echo "❌ 构建失败，请检查错误信息"
    exit 1
fi

echo ""
echo "构建完成！"
echo ""
echo "使用说明:"
echo "1. 解压: tar -xzf ${RELEASE_DIR}.tar.gz"
echo "2. 进入: cd $RELEASE_DIR"
echo "3. 启动: ./start.sh 或 ./start_daemon.sh" 