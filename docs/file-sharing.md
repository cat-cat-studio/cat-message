# 文件分享功能文档

## 功能概述

Cat-Message v2.0 支持发送任意类型的文件，包括文档、图片、程序、压缩包等。文件通过加密传输，存储在服务器端，并自动下载到客户端本地，支持直接拖拽操作。

## 🚀 快速使用指南

### 发送文件
1. 点击客户端的"发送文件"按钮
2. 选择要发送的文件
3. 文件会自动上传并分享给其他用户

### 接收文件
1. 文件消息出现在聊天界面
2. 文件自动下载到本地临时目录
3. 从聊天界面直接拖拽文件到文件管理器或其他应用
4. 或双击文件夹路径打开文件位置

## 功能特性

### 📁 支持的文件类型
- 文档文件：PDF, DOC, TXT, PPT 等
- 图片文件：PNG, JPG, GIF, BMP 等
- 压缩文件：ZIP, RAR, 7Z 等
- 程序文件：EXE, APK, DMG 等
- 其他任意格式文件

### 📏 文件大小限制
- **默认设置**：无大小限制
- **可配置**：通过 `config.ini` 设置限制
- **服务器端检查**：防止过大文件占用存储空间

### 🔐 安全特性
- **加密传输**：文件内容同样经过RSA加密
- **UUID存储**：服务器使用随机ID存储文件
- **原名保护**：保留原始文件名，便于下载

### 🎯 拖拽功能
- **自动下载**：接收的文件自动下载到本地临时目录
- **直接拖拽**：可从聊天界面直接拖拽文件到文件管理器
- **一键打开**：双击可直接打开文件所在文件夹
- **右键菜单**：支持右键复制路径和打开文件夹
- **缓存管理**：菜单栏"清理缓存"功能，一键清理所有下载文件

## 使用方法

### 发送文件

1. **打开客户端**，连接到服务器
2. **点击"发送文件"按钮**
3. **选择要发送的文件**
4. **确认发送**，等待上传完成

### 接收文件

1. **查看文件消息**：显示文件名和大小
2. **自动下载**：文件自动下载到本地临时目录
3. **拖拽使用**：直接从聊天界面拖拽文件到文件管理器或其他应用
4. **打开文件夹**：双击文件夹路径或右键选择"打开文件夹"
5. **复制路径**：右键选择"复制路径"获取文件位置

### 缓存管理

1. **查看缓存**：文件存储在系统临时目录的 `cat_message_files` 文件夹中
2. **清理缓存**：点击菜单栏的"清理缓存"按钮
3. **确认清理**：系统会显示缓存位置和文件信息，确认后清理
4. **查看结果**：显示清理的文件数量和释放的空间大小

## 配置文件大小限制

### 启用文件大小限制

编辑服务器的 `config.ini` 文件：

```ini
[file_settings]
enable_file_limit = true
max_file_size_mb = 50
```

### 配置选项说明

| 配置项 | 值 | 说明 |
|--------|------|------|
| enable_file_limit | true/false | 是否启用文件大小限制 |
| max_file_size_mb | 数字 | 文件大小限制（MB），0表示无限制 |

### 配置示例

#### 限制文件为10MB
```ini
[file_settings]
enable_file_limit = true
max_file_size_mb = 10
```

#### 限制文件为100MB
```ini
[file_settings]
enable_file_limit = true
max_file_size_mb = 100
```

#### 取消文件大小限制
```ini
[file_settings]
enable_file_limit = false
max_file_size_mb = 0
```

## 存储结构

### 服务器端文件组织

```
cat-message-server/
├── file_storage/              # 文件存储目录
│   ├── uuid1                  # 实际文件数据
│   ├── uuid1.meta            # 文件元数据（原始文件名等）
│   ├── uuid2
│   ├── uuid2.meta
│   └── ...
├── image_storage/            # 图片存储目录
├── chat.json                # 聊天记录
└── server.log               # 服务器日志
```

### 客户端本地存储

```
系统临时目录/cat_message_files/
├── file1.pdf                 # 接收的文件（保持原名）
├── document.docx            # 接收的文件（保持原名）
├── image.png               # 接收的文件（保持原名）
└── ...
```

**注意**：客户端文件存储在系统临时目录，可能会被系统清理程序定期删除。

### 元数据格式

每个文件都有对应的 `.meta` 文件，包含：
```json
{
    "original_name": "example.pdf"
}
```

## 下载方式

### HTTP下载服务

- **端口**：12346（固定）
- **URL格式**：`http://服务器IP:12346/file/文件UUID`
- **文件名**：自动设置为原始文件名

### 浏览器兼容性

支持所有现代浏览器：
- Chrome, Firefox, Safari, Edge
- 移动浏览器：Chrome Mobile, Safari Mobile

## 故障排除

### 文件发送失败

#### 可能原因
1. **文件过大**：超过服务器配置的大小限制
2. **网络中断**：传输过程中连接断开
3. **磁盘空间不足**：服务器存储空间不够

#### 解决方法
1. **检查文件大小**：确认是否超过限制
2. **查看服务器日志**：检查 `server.log` 中的错误信息
3. **重新发送**：网络恢复后重试

### 文件下载失败

#### 可能原因
1. **链接过期**：文件可能已被删除
2. **网络问题**：无法连接到服务器
3. **端口被阻止**：防火墙阻止12346端口

#### 解决方法
1. **检查链接**：确认URL格式正确
2. **检查网络**：确认能正常访问服务器
3. **检查防火墙**：确保12346端口开放

## 最佳实践

### 文件管理建议

1. **定期清理**：定期删除不需要的文件
2. **备份重要文件**：不要完全依赖聊天工具存储
3. **合理命名**：使用清晰的文件名
4. **本地存储**：重要文件及时从临时目录移动到安全位置
5. **拖拽使用**：充分利用拖拽功能快速管理文件
6. **缓存清理**：定期使用"清理缓存"功能释放磁盘空间

### 安全建议

1. **敏感文件**：重要文件建议使用高等级加密模式
2. **访问控制**：限制服务器访问权限
3. **定期更新**：保持服务器软件最新

### 性能优化

1. **文件大小**：根据网络情况设置合理的大小限制
2. **存储清理**：定期清理旧文件释放空间
3. **网络优化**：确保服务器有足够的带宽

## 技术细节

### 文件传输流程

1. **客户端选择文件** → **读取文件数据**
2. **Base64编码** → **RSA加密传输**
3. **服务器接收** → **解密并保存**
4. **生成UUID** → **返回文件ID**
5. **广播消息** → **客户端自动下载**
6. **本地存储** → **支持拖拽操作**

### 存储机制

- **UUID命名**：避免文件名冲突和直接访问
- **元数据分离**：文件数据和信息分开存储
- **HTTP服务**：独立的文件下载服务

### 安全机制

- **传输加密**：文件内容经过RSA加密
- **访问控制**：通过UUID控制文件访问
- **日志记录**：记录所有文件操作 