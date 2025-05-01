# 🐾 WP Enumeration Tool

Welcome to the **WP Enumeration Tool**! This Python script is designed to help security researchers and developers identify potential vulnerabilities in WordPress sites by enumerating users, checking for accessible files, and testing various endpoints. 🚀

## 📋 Features

- **User Enumeration**: Discover WordPress users through the REST API and individual user endpoints. 👤
- **Admin Login Check**: Verify the existence of common WordPress login paths. 🔑
- **Uploads Accessibility Check**: Check if the `wp-content/uploads` directory is accessible. 📂
- **XML-RPC Testing**: Test for the presence of `xmlrpc.php` for potential pingback and brute force attacks. ⚔️
- **Configuration File Check**: Attempt to download sensitive configuration files like `wp-config.php`. 📄
- **oEmbed Proxy Check**: Test for SSRF vulnerabilities via the oEmbed proxy. 🌐

## ⚙️ Requirements

- Python 3.x
- `requests` library (install via `pip install requests`)

## 📥 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/wp-enumeration-tool.git
   cd wp-enumeration-tool
