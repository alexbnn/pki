# PKI Management System with SCEP Support

A containerized Public Key Infrastructure (PKI) management system that provides a web interface for EasyRSA certificate operations with SCEP (Simple Certificate Enrollment Protocol) support and role-based access control.

## Features

### 🔐 Multi-User Authentication & Authorization
- **Role-based access control** with three user types:
  - **Admin**: Full system access including user management and PKI initialization
  - **Operator**: Standard PKI operations (create, revoke, renew certificates) except PKI initialization
  - **Viewer**: Read-only access to certificates and PKI status
- **Secure authentication** with bcrypt password hashing
- **Session management** with PostgreSQL backend
- **Password reset** functionality for logged-in users

### 📜 Certificate Management
- **PKI Initialization**: Set up Certificate Authority infrastructure
- **CA Management**: Build and configure Certificate Authorities
- **Certificate Operations**: Create, view, revoke, and renew certificates
- **Multiple formats**: Support for various certificate formats (.crt, .p12, .ovpn, etc.)
- **Certificate Revocation Lists (CRL)**: Generate and manage CRLs
- **Bulk operations**: Efficient handling of multiple certificates

### 🌐 SCEP Protocol Support
- **Device enrollment**: Automated certificate enrollment for network devices
- **Challenge-based authentication**: Secure device registration
- **Standards compliance**: Full SCEP protocol implementation

### 🏗️ Production-Ready Architecture
- **Containerized deployment** with Docker Compose
- **Nginx reverse proxy** with SSL termination and security headers
- **PostgreSQL database** for user data and audit logs
- **Redis caching** for session management and rate limiting
- **Comprehensive logging** and audit trails
- **Health monitoring** endpoints

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd ca_3.0
```

2. **Run the setup script**:
```bash
./setup.sh
```

3. **Start the services**:
```bash
docker-compose up -d
```

4. **Access the web interface**:
   - **HTTPS**: https://localhost (recommended)
   - **HTTP**: http://localhost (redirects to HTTPS)

### Default User Accounts

The system automatically creates three default users:

| Username | Password  | Role     | Permissions |
|----------|-----------|----------|-------------|
| admin    | admin     | Admin    | Full system access, user management, PKI init |
| operator | operator  | Operator | All PKI operations except initialization |
| viewer   | viewer    | Viewer   | Read-only access to certificates |

**⚠️ Change default passwords in production!**

## API Documentation

### Authentication Endpoints
```bash
# Login
POST /login
Content-Type: application/json
{"username": "admin", "password": "admin"}

# Logout  
POST /logout

# Change password
POST /api/profile/change-password
{"current_password": "old", "new_password": "new"}
```

### PKI Operations
```bash
# Initialize PKI
POST /api/pki/init

# Build CA
POST /api/ca/build
{"common_name": "My CA", "country": "US", "province": "CA"}

# Create certificate
POST /api/certificates/create-full
{"name": "client1", "type": "client"}

# List certificates
GET /api/certificates/list

# Revoke certificate
POST /api/certificates/revoke
{"name": "client1", "reason": "superseded"}
```

### User Management (Admin only)
```bash
# List users
GET /api/users/list

# Create user
POST /api/users/create
{"username": "newuser", "password": "password", "email": "user@example.com", "role": "operator"}

# Delete user
DELETE /api/users/delete/{username}
```

## Architecture

### Services
- **web-interface**: Flask application with REST API and web UI
- **easyrsa-container**: EasyRSA command wrapper service
- **nginx**: Reverse proxy with SSL termination and security headers
- **postgres**: User authentication and audit database
- **redis**: Session storage and rate limiting
- **scep-server**: SCEP protocol implementation for device enrollment

### Data Persistence
All data is stored in local folders for easy backup and management:
- `./easyrsa-pki`: PKI certificates and keys
- `./postgres-data`: User database
- `./redis-data`: Session cache
- `./logs`: Application logs

### Security Features
- **HTTPS enforcement** with self-signed certificates
- **Security headers**: HSTS, CSP, X-Frame-Options
- **Rate limiting** via Redis and Nginx
- **Input validation** and SQL injection protection
- **Audit logging** for all operations
- **Container security** with non-root users

## Configuration

### Environment Variables
Key configuration options in `.env`:
```bash
# Database
POSTGRES_USER=pkiuser
POSTGRES_PASSWORD=pkipass
POSTGRES_DB=pkiauth

# Security
SECRET_KEY=your-secret-key
AUTHENTICATION_ENABLED=true
MULTI_USER_MODE=true

# Certificate defaults
EASYRSA_REQ_COUNTRY=US
EASYRSA_REQ_PROVINCE=California
EASYRSA_REQ_CITY=San Francisco
EASYRSA_REQ_ORG=My Organization
```

### SSL Certificates
The system includes self-signed certificates in `./ssl/`:
- `server.crt`: SSL certificate
- `server.key`: Private key

For production, replace with valid certificates from a trusted CA.

## Development

### Container Management
```bash
# View logs
docker-compose logs -f

# Access container shells
docker-compose exec web-interface /bin/bash
docker-compose exec easyrsa-container /bin/bash

# Rebuild containers
docker-compose build --no-cache

# Stop services
docker-compose down
```

### Health Checks
```bash
# Web interface via nginx
curl -k https://localhost/health

# EasyRSA container direct
curl http://localhost:8080/health

# Nginx status
curl http://localhost:8081/nginx-status
```

### Database Access
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U pkiuser -d pkiauth

# Redis CLI
docker-compose exec redis redis-cli
```

## Monitoring & Troubleshooting

### Log Locations
- **Application logs**: `./logs/app.log`
- **Nginx logs**: `./logs/access.log`, `./logs/error.log`
- **EasyRSA logs**: `./logs/easyrsa/`
- **Audit logs**: Database table `audit_logs`

### Common Issues
1. **Port conflicts**: Ensure ports 80, 443, 5432, 6379, 8080, 8090 are available
2. **Permission errors**: Check Docker daemon permissions
3. **Certificate issues**: Verify PKI initialization completed successfully
4. **Database connection**: Check PostgreSQL container status and credentials

### Performance Tuning
- **Memory limits**: Configured in docker-compose.yml
- **Redis cache**: Adjust `maxmemory` settings
- **Connection pooling**: Configure in database settings
- **Rate limiting**: Adjust nginx and Redis rate limits

## Support

For issues and questions:
- Check the logs in `./logs/` directory
- Review health check endpoints
- Examine container status with `docker-compose ps`
- Check database connectivity and initialization

---

**Security Note**: This system includes self-signed certificates and default credentials. Always change default passwords and use proper SSL certificates in production environments.
