# Chronoflow

A comprehensive web-based time tracking application built with Flask, designed specifically for freelancers and consultants who need robust time tracking, project management, and client billing capabilities.

### Disclaimer

This project has been completely built with Claude Sonnet 4 primarily using Claude Code. This was my first attempt to build something without touching the codebase myself and I find this result quite good. It definitely saved me countless hours writing it myself.

That being said, I tried to have an eye on security as well but if you encounter bugs or security issues, feel free to open a PR.

## 🚀 Features

### 🔐 Security & Authentication
- **Multi-user support** with secure email/password authentication
- **Two-Factor Authentication (2FA)** with TOTP support (Google Authenticator compatible)
- **Backup codes** for 2FA recovery (10 unique codes per user)
- **CSRF protection** with Flask-WTF
- **Rate limiting** (200 requests/day, 50/hour) to prevent abuse
- **Per-user SQLite databases** for complete data isolation
- **Secure session management** with automatic logout

### ⏱️ Time Tracking
- **Live timer** with real-time display and controls
- **Project-based time tracking** with required project selection
- **Manual time entry** for backdating or offline work
- **Multiple billing increments**: Per minute, 15-minute, 30-minute, or hourly
- **Automatic earnings calculation** based on project hourly rates
- **Duration validation** with minimum 1-minute billing
- **Timer persistence** during modal interactions

### 📊 Project Management
- **Unlimited projects** with custom names and hourly rates
- **Flexible billing increments** per project
- **Project archiving system** (soft delete preserving historical data)
- **Real-time project updates** in dropdowns and filters
- **Archived project handling** in filters and exports

### 💰 Billing & Invoice Management
- **Three-state billing system**:
  - **Pending**: Default state for new entries
  - **Invoiced**: Entry has been billed to client
  - **Unbilled**: Entry will not be billed
- **Bulk billing status updates**
- **Edit protection** for invoiced/unbilled entries
- **Visual status indicators** with color-coded rows and badges
- **Legacy invoiced field support** for backward compatibility

### 📤 Export & Import Capabilities
- **Multiple export formats**: CSV, JSON, Excel (XLSX)
- **Dual export modes**:
  - **Standard export**: Full data for analysis
  - **Customer export**: Client-friendly format with limited columns
- **Filtered exports** using current view settings
- **Full backup export** for complete data migration
- **JSON import system** with data validation and merge options
- **Batch data operations** with progress reporting

### 📈 Dashboard & Analytics
- **Live summary cards** showing:
  - Total hours tracked
  - Total earnings calculated
  - Number of time entries
- **Sortable data table** with columns:
  - Date, Project, Time Period, Description, Duration, Earnings, Status
- **Color-coded entries** for different billing statuses
- **Real-time updates** based on applied filters

### 📱 User Experience
- **Responsive Bootstrap 5 design** for desktop and mobile
- **Modal-based workflows** for project management and manual entry
- **Confirmation dialogs** for destructive actions
- **Loading states** and progress indicators
- **Error handling** with user-friendly messages
- **Smart defaults** for time entries
- **Accessibility features** with proper labeling and keyboard support

## 📋 Requirements

### System Requirements
- Python 3.8+
- SQLite 3.x
- Modern web browser (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)

### Python Dependencies

**Development:**
```
Flask==2.3.3
Werkzeug==2.3.7
pyotp==2.9.0
qrcode[pil]==7.4.2
Flask-Limiter==3.5.0
Flask-WTF==1.2.1
```

**Production (includes all development dependencies plus):**
```
gunicorn==21.2.0
```

## 🛠️ Installation

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd chronoflow
   ```

2. **Create and activate virtual environment:**
   ```bash
   python -m venv chronoflow_env
   
   # On macOS/Linux:
   source chronoflow_env/bin/activate
   
   # On Windows:
   chronoflow_env\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create configuration file:**
   ```bash
   cp config.json.dist config.json
   ```
   
   Edit `config.json` to customize settings (especially the secret key for production).

5. **Run the development server:**
   ```bash
   python app.py
   ```

6. **Access the application:**
   Open http://localhost:5000 in your browser

### Production Deployment

#### Using Gunicorn (Recommended)

1. **Install production dependencies:**
   ```bash
   pip install -r requirements-prod.txt
   ```

2. **Create and configure production config:**
   ```bash
   cp config.json.dist config.json
   ```
   
   Edit `config.json` and update:
   - `flask.secret_key`: Use a secure random secret key
   - `flask.env`: Set to "production"
   - `registration.enabled`: Set to false if you want to disable registration
   
   Or use environment variables (they take precedence over config file):
   ```bash
   export FLASK_SECRET_KEY="your-secure-random-secret-key-here"
   export DATABASE_FOLDER="/path/to/databases"
   ```

3. **Run with Gunicorn:**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:8000 app:app
   ```

#### Using Docker

Create a `Dockerfile`:
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
```

Build and run:
```bash
docker build -t chronoflow .
docker run -p 8000:8000 -v $(pwd)/user_databases:/app/user_databases chronoflow
```

#### Using Systemd Service

Create `/etc/systemd/system/chronoflow.service`:
```ini
[Unit]
Description=Chronoflow Time Tracking Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/chronoflow
Environment=PATH=/path/to/chronoflow/venv/bin
Environment=FLASK_ENV=production
Environment=FLASK_SECRET_KEY=your-secret-key
ExecStart=/path/to/chronoflow/venv/bin/gunicorn -w 4 -b 0.0.0.0:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable chronoflow
sudo systemctl start chronoflow
```

#### Using SysV Init (Devuan, older Debian/Ubuntu)

For systems using SysV init instead of systemd:

1. **Copy the init script:**
   ```bash
   sudo cp chronoflow-init /etc/init.d/chronoflow
   sudo chmod +x /etc/init.d/chronoflow
   ```

2. **Set environment variables:**
   ```bash
   sudo nano /etc/default/chronoflow
   ```
   
   Add:
   ```bash
   FLASK_SECRET_KEY="your-secure-random-secret-key-here"
   ```

3. **Update the script paths:**
   Edit `/etc/init.d/chronoflow` and update:
   - `ROOT_DIR="/path/to/your/chronoflow"` 
   - `USER="your-app-user"`

4. **Enable and start:**
   ```bash
   sudo update-rc.d chronoflow defaults
   sudo service chronoflow start
   ```

5. **Check status:**
   ```bash
   sudo service chronoflow status
   ```

#### Nginx Reverse Proxy

Add to Nginx configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🎯 Usage Guide

### First-Time Setup

1. **Register an Account:**
   - Navigate to the registration page
   - Enter email and secure password
   - Complete registration

2. **Setup Two-Factor Authentication:**
   - Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
   - Or enter secret key manually
   - Save backup codes in a secure location
   - Complete 2FA verification

3. **Create Your First Project:**
   - Open Project Manager
   - Click "Add New Project"
   - Enter project name and hourly rate
   - Select billing increment (per minute, 15min, 30min, or hourly)
   - Save project

### Daily Workflow

1. **Start Tracking Time:**
   - Select project from dropdown
   - Click "Start" to begin timer
   - Work on your project

2. **Stop and Describe Work:**
   - Click "Stop" when finished
   - Add description of work performed
   - Entry is automatically saved with earnings calculated

3. **Manual Time Entry:**
   - Use "Manual Entry" button for offline work
   - Set start/end times
   - Select project and add description
   - Submit entry

4. **Review and Filter:**
   - Use filters to view specific projects or date ranges
   - Check billing status of entries
   - Sort by any column

5. **Export for Billing:**
   - Apply filters for specific client/project
   - Use "Export (Customer)" for client-friendly format
   - Generate CSV or Excel files for invoicing

### Project Management

- **Edit Projects:** Click "Manage Projects" to modify rates or names
- **Archive Projects:** Archive completed projects (preserves data)
- **Reactivate:** Unarchive projects when needed
- **Billing Increments:** Set how time should be rounded (great for different client requirements)

### Billing Status Workflow

1. **Pending** (default): New time entries
2. **Mark as Invoiced**: When you bill the client
3. **Mark as Unbilled**: For internal time or non-billable work

### Export Options

- **Standard Export**: Full data export for your records
- **Customer Export**: Clean format suitable for client invoices
- **Filtered Export**: Only exports entries matching current filters
- **Full Backup**: Complete database backup for migration/backup

## 🏗️ Architecture

### Database Structure

```
chronoflow/
├── main.db                    # Main authentication database
│   └── users                  # User accounts, 2FA settings
├── user_databases/            # Per-user data isolation
│   ├── user_<uuid>.db        # Individual user databases
│   │   ├── projects          # Project definitions
│   │   └── time_entries      # Time tracking data
└── user_databases_backup_*/   # Automatic backups
```

### File Organization

```
chronoflow/
├── app.py                     # Main Flask application
├── config.json.dist          # Configuration template (copy to config.json)
├── config.json               # Application configuration (not in repo)
├── requirements.txt           # Python dependencies (development)
├── requirements-prod.txt      # Production dependencies
├── main.db                   # Main user database
├── user_databases/           # Per-user databases
├── templates/                # HTML templates
│   ├── base.html            # Base template with navigation
│   ├── login.html           # Login with 2FA support
│   ├── register.html        # User registration
│   ├── registration_disabled.html # Registration disabled page
│   ├── setup_2fa.html       # 2FA setup with QR codes
│   ├── change_password.html # Password change form
│   └── dashboard.html       # Main application interface
└── README.md                # This file
```

## 🔌 API Reference

### Authentication Endpoints
- `POST /register` - User registration
- `POST /login` - User login with 2FA
- `GET /setup_2fa` - 2FA setup page
- `POST /verify_2fa` - Verify 2FA code
- `GET /change_password` - Password change form
- `POST /change_password` - Process password change
- `GET /logout` - User logout

### Project Management API
- `GET /api/projects` - List projects (supports `?include_archived=true`)
- `POST /api/projects` - Create new project
- `PUT /api/projects/<id>` - Update project
- `POST /api/projects/<id>/archive` - Archive project
- `POST /api/projects/<id>/unarchive` - Unarchive project

### Time Entry API
- `GET /api/time_entries` - List entries with filtering
  - Query parameters: `project_id`, `date_from`, `date_to`, `billing_statuses`, `limit`
- `POST /api/time_entries` - Create time entry
- `PUT /api/time_entries/<id>` - Update time entry
- `DELETE /api/time_entries/<id>` - Delete time entry
- `POST /api/time_entries/<id>/billing_status` - Update billing status

### Export/Import API
- `GET /api/export` - Export data in various formats
  - Query parameters: `format`, `project_id`, `date_from`, `date_to`, `billing_statuses`, `customer_export`
- `POST /api/import` - Import data from JSON backup

### Security API
- `GET /api/2fa_status` - Check 2FA status
- `POST /api/disable_2fa` - Disable 2FA
- `POST /api/verify_password_for_backup_codes` - Verify password to view backup codes

## 🔧 Configuration

### Configuration File

Chronoflow uses a `config.json` file for application settings. Copy `config.json.dist` to `config.json` and customize as needed.

**Setup:**
```bash
cp config.json.dist config.json
```

**config.json structure:**
```json
{
    "flask": {
        "secret_key": "your-secret-key-change-this-in-production",
        "env": "development",
        "database_folder": "user_databases"
    },
    "registration": {
        "enabled": true,
        "rate_limit": "5 per minute",
        "require_2fa": true,
        "message_when_disabled": "Registration is currently disabled. Please contact the administrator."
    },
    "security": {
        "min_processing_time": 0.1,
        "csrf_protection": true
    }
}
```

**Configuration Options:**

- `flask.secret_key`: Flask secret key (override with FLASK_SECRET_KEY env var)
- `flask.env`: Environment (development/production)
- `flask.database_folder`: Database directory (override with DATABASE_FOLDER env var)
- `registration.enabled`: Enable/disable user registration
- `registration.rate_limit`: Rate limiting for registration attempts
- `registration.require_2fa`: Whether 2FA is required (currently always true)
- `registration.message_when_disabled`: Message shown when registration is disabled
- `security.min_processing_time`: Minimum processing time to prevent timing attacks
- `security.csrf_protection`: Enable CSRF protection (currently always true)

### Environment Variables

Environment variables take precedence over config file settings:

```bash
# Optional (overrides config.json values)
FLASK_SECRET_KEY="your-secure-random-secret-key"
DATABASE_FOLDER="/path/to/databases"
```

### Security Configuration

- **Change secret key** for production deployments
- **Enable HTTPS** for production use
- **Configure rate limiting** based on your needs
- **Set up regular backups** of user databases
- **Monitor logs** for security events
- **Disable registration** if needed using config.json

## 🐛 Troubleshooting

### Common Issues

**"Module not found" errors:**
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt`
- Check Python version compatibility

**Database permission errors:**
- Verify write permissions in application directory
- Check SQLite installation
- Ensure user_databases directory exists

**2FA setup problems:**
- Verify system time is synchronized
- Try manual secret entry if QR code fails
- Check authenticator app compatibility
- Use backup codes if needed

**Timer not working:**
- Check JavaScript console for errors
- Verify project is selected before starting
- Clear browser cache and cookies

**Export functionality issues:**
- Verify all dependencies are installed
- Check browser popup blocker settings
- Ensure sufficient disk space

### Development Debugging

Enable debug mode in development:
```python
if __name__ == '__main__':
    init_main_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Logs and Monitoring

- Check Flask application logs for errors
- Monitor database file sizes
- Set up log rotation for production
- Use application performance monitoring tools

## 🔄 Migration and Backup

### Backup Strategy

1. **Automatic Backups**: Application creates backups during major operations
2. **Manual Backup**: Use export functionality to create JSON backups
3. **Database Files**: Copy `main.db` and `user_databases/` directory
4. **Scheduled Backups**: Set up cron jobs for regular backups

### Migration Between Servers

1. **Export Data**: Use full backup export feature
2. **Install Application**: Set up Chronoflow on new server
3. **Import Data**: Use import functionality to restore data
4. **Verify**: Test all functionality after migration

## 📱 Mobile Support

Chronoflow is fully responsive and optimized for mobile devices:
- **iOS Safari** - Full functionality
- **Android Chrome** - Complete feature support
- **Mobile browsers** - Bootstrap 5 responsive design
- **Touch-friendly** - Large buttons and touch targets
- **Offline-capable** - Manual entry for offline work

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the [MIT LICENSE](LICENSE).

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the API documentation
3. Check browser developer console for errors
4. Verify all dependencies are installed correctly

---

**Chronoflow** - Professional time tracking for freelancers and consultants