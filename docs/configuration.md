# Cat-Message 配置文档

## config.ini 配置说明

Cat-Message 服务器的配置文件为 `config.ini`，首次运行服务器时会自动生成默认配置。

### 配置文件结构

```ini
[database]
port = 12345

[file_settings]
max_file_size_mb = 0
enable_file_limit = false
```

### 配置项详细说明

#### [database] 节

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| port | 12345 | 聊天服务监听端口 |

**注意：** 图片和文件下载服务固定使用端口 12346

#### [file_settings] 节

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| enable_file_limit | false | 是否启用文件大小限制 |
| max_file_size_mb | 0 | 文件大小限制（MB），0表示无限制 |

### 配置示例

#### 示例1：无文件大小限制（默认）
```ini
[database]
port = 12345

[file_settings]
max_file_size_mb = 0
enable_file_limit = false
```

#### 示例2：限制文件大小为50MB
```ini
[database]
port = 12345

[file_settings]
max_file_size_mb = 50
enable_file_limit = true
```

#### 示例3：自定义端口和文件限制
```ini
[database]
port = 8888

[file_settings]
max_file_size_mb = 100
enable_file_limit = true
```

### 配置修改方法

1. **停止服务器**：在服务器控制台输入 `stop`
2. **编辑配置文件**：使用文本编辑器修改 `config.ini`
3. **重启服务器**：重新运行服务器程序

### 注意事项

1. **端口冲突**：确保配置的端口未被其他程序占用
2. **防火墙设置**：修改端口后需要在防火墙中开放新端口
3. **文件限制**：
   - `enable_file_limit = false` 时，`max_file_size_mb` 设置无效
   - `max_file_size_mb = 0` 表示无大小限制
   - 文件大小检查在服务器端进行，客户端不会预检查
4. **配置生效**：配置修改后需要重启服务器才能生效

### 推荐配置

#### 个人/小团队使用
```ini
[database]
port = 12345

[file_settings]
max_file_size_mb = 50
enable_file_limit = true
```

#### 企业/大团队使用
```ini
[database]
port = 12345

[file_settings]
max_file_size_mb = 100
enable_file_limit = true
```

#### 本地测试
```ini
[database]
port = 12345

[file_settings]
max_file_size_mb = 0
enable_file_limit = false
```

### 故障排除

#### 文件发送失败
1. 检查 `enable_file_limit` 是否为 `true`
2. 检查文件大小是否超过 `max_file_size_mb` 限制
3. 查看服务器日志 `server.log` 获取详细错误信息

#### 端口连接失败
1. 检查端口是否被占用：`netstat -an | findstr :12345`
2. 检查防火墙设置
3. 确认配置文件中的端口设置正确 