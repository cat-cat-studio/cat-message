#!/bin/bash

# Cat Message 客户端 Linux 一体包构建脚本
# Build script for Cat Message Client Linux standalone package

echo "===================================="
echo "Cat Message 客户端 Linux 构建工具"
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

# 检查src/user.py是否存在
if [ ! -f "src/user.py" ]; then
    echo "错误: 未找到src/user.py文件"
    exit 1
fi

echo "开始构建客户端..."

# 创建Linux专用的spec文件
cat > client_linux.spec << 'EOF'
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/user.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtGui', 
        'PyQt6.QtWidgets',
        'Crypto.PublicKey.RSA',
        'Crypto.Cipher.PKCS1_OAEP',
        'requests'
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
    name='cat-message-client-linux',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
EOF

# 使用PyInstaller构建
echo "正在使用PyInstaller构建..."
pyinstaller --clean client_linux.spec

# 检查构建结果
if [ -f "dist/cat-message-client-linux" ]; then
    echo ""
    echo "🎉 构建成功！"
    echo "可执行文件位置: dist/cat-message-client-linux"
    echo ""
    
    # 创建发布目录
    echo "正在创建发布包..."
    RELEASE_DIR="cat-message-client-linux-$(date +%Y%m%d)"
    mkdir -p "$RELEASE_DIR"
    
    # 复制可执行文件
    cp "dist/cat-message-client-linux" "$RELEASE_DIR/"
    
    # 创建启动脚本
    cat > "$RELEASE_DIR/start.sh" << 'STARTEOF'
#!/bin/bash
cd "$(dirname "$0")"
./cat-message-client-linux
STARTEOF
    chmod +x "$RELEASE_DIR/start.sh"
    
    # 创建说明文件
    cat > "$RELEASE_DIR/README.txt" << 'READMEEOF'
Cat Message 客户端 Linux 版
===========================

运行方法:
1. 双击 start.sh 启动
   或
2. 在终端中运行: ./cat-message-client-linux

注意事项:
- 确保服务器已经运行
- 默认连接端口为 12345
- 支持RSA加密（无加密/RSA2048/RSA4096/RSA8192）
- 支持文件和图片发送
- 支持文件拖拽保存

如有问题，请检查终端输出信息。

构建时间: $(date)
READMEEOF
    
    # 设置可执行权限
    chmod +x "$RELEASE_DIR/cat-message-client-linux"
    
    # 创建tar.gz压缩包
    tar -czf "${RELEASE_DIR}.tar.gz" "$RELEASE_DIR"
    
    echo "📦 发布包已创建:"
    echo "  目录: $RELEASE_DIR/"
    echo "  压缩包: ${RELEASE_DIR}.tar.gz"
    echo ""
    echo "文件大小:"
    ls -lh "$RELEASE_DIR/cat-message-client-linux"
    ls -lh "${RELEASE_DIR}.tar.gz"
    
else
    echo "❌ 构建失败，请检查错误信息"
    exit 1
fi

echo ""
echo "构建完成！" 