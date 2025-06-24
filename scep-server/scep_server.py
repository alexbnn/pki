# scep_server.py - SCEP (Simple Certificate Enrollment Protocol) Server
# This server provides SCEP endpoints for device certificate enrollment

from flask import Flask, request, Response, jsonify
import requests
import os
import base64
import logging
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import tempfile

app = Flask(__name__)

# Configuration
EASYRSA_CONTAINER_URL = os.getenv('EASYRSA_CONTAINER_URL', 'http://easyrsa-container:8080')
SCEP_CA_IDENTIFIER = os.getenv('SCEP_CA_IDENTIFIER', 'pkiclient')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/scep.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# SCEP Content Types
SCEP_CONTENT_TYPE = 'application/x-pki-message'
SCEP_CA_CERT_CONTENT_TYPE = 'application/x-x509-ca-cert'
SCEP_CA_CHAIN_CONTENT_TYPE = 'application/x-x509-ca-ra-cert-chain'

# SCEP Operations
SCEP_OPERATIONS = {
    'GetCACert': 'Get CA Certificate',
    'GetCACaps': 'Get CA Capabilities', 
    'PKIOperation': 'Certificate Enrollment/Renewal'
}

@app.route('/health')
def health():
    """Health check endpoint with faster timeout for responsiveness"""
    try:
        # Quick health check with short timeout to avoid blocking
        response = requests.get(f"{EASYRSA_CONTAINER_URL}/health", timeout=3)
        easyrsa_healthy = response.status_code == 200
        
        return jsonify({
            "status": "healthy" if easyrsa_healthy else "degraded",
            "scep_server": "online",
            "easyrsa_connection": "healthy" if easyrsa_healthy else "unhealthy",
            "timestamp": datetime.now().isoformat()
        }), 200
    except requests.exceptions.Timeout:
        logger.warning("Health check timeout - EasyRSA container may be busy")
        return jsonify({
            "status": "degraded",
            "scep_server": "online",
            "easyrsa_connection": "timeout",
            "message": "EasyRSA container timeout (may be busy)",
            "timestamp": datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 503

@app.route('/scep')
def scep_info():
    """SCEP endpoint information"""
    return jsonify({
        "scep_server": "Extreme Networks PKI SCEP Server",
        "version": "1.0",
        "supported_operations": SCEP_OPERATIONS,
        "endpoints": {
            "scep_url": f"{request.host_url}scep/{SCEP_CA_IDENTIFIER}",
            "getcacert": f"{request.host_url}scep/{SCEP_CA_IDENTIFIER}?operation=GetCACert",
            "getcacaps": f"{request.host_url}scep/{SCEP_CA_IDENTIFIER}?operation=GetCACaps"
        },
        "ca_identifier": SCEP_CA_IDENTIFIER
    })

@app.route(f'/scep/{SCEP_CA_IDENTIFIER}', methods=['GET', 'POST'])
def scep_endpoint():
    """Main SCEP endpoint for certificate operations"""
    try:
        operation = request.args.get('operation')
        message = request.args.get('message')
        
        logger.info(f"SCEP {request.method} request - Operation: {operation}")
        
        if request.method == 'GET':
            if operation == 'GetCACert':
                return handle_get_ca_cert()
            elif operation == 'GetCACaps':
                return handle_get_ca_caps()
            else:
                return jsonify({"error": "Invalid operation"}), 400
                
        elif request.method == 'POST':
            if operation == 'PKIOperation':
                return handle_pki_operation()
            else:
                return jsonify({"error": "Invalid operation"}), 400
                
    except Exception as e:
        logger.error(f"SCEP endpoint error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_get_ca_cert():
    """Handle GetCACert operation - return CA certificate"""
    try:
        logger.info("Handling GetCACert request")
        
        # Get CA certificate from EasyRSA container with longer timeout
        response = requests.post(
            f"{EASYRSA_CONTAINER_URL}/execute",
            json={"operation": "show-ca"},
            timeout=60
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get CA info: {response.status_code}")
            return jsonify({"error": "CA not available"}), 503
            
        ca_info = response.json()
        if ca_info.get('status') != 'success':
            logger.error(f"CA show failed: {ca_info.get('message')}")
            return jsonify({"error": "CA not available"}), 503
        
        # Download CA certificate file with longer timeout
        ca_response = requests.get(f"{EASYRSA_CONTAINER_URL}/download-ca", timeout=60)
        if ca_response.status_code != 200:
            logger.error("Failed to download CA certificate")
            return jsonify({"error": "CA certificate not available"}), 503
            
        ca_cert_data = ca_response.content
        
        logger.info("Successfully retrieved CA certificate")
        return Response(
            ca_cert_data,
            mimetype=SCEP_CA_CERT_CONTENT_TYPE,
            headers={
                'Content-Disposition': 'attachment; filename="ca.crt"',
                'Content-Length': str(len(ca_cert_data))
            }
        )
        
    except Exception as e:
        logger.error(f"GetCACert error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_get_ca_caps():
    """Handle GetCACaps operation - return CA capabilities"""
    try:
        logger.info("Handling GetCACaps request")
        
        # Define SCEP capabilities
        capabilities = [
            "Renewal",          # Certificate renewal
            "SHA-1",           # SHA-1 hash algorithm
            "SHA-256",         # SHA-256 hash algorithm  
            "DES3",            # 3DES encryption
            "AES",             # AES encryption
            "POSTPKIOperation", # POST for PKI operations
        ]
        
        caps_text = "\n".join(capabilities)
        
        logger.info(f"Returning CA capabilities: {capabilities}")
        return Response(
            caps_text,
            mimetype='text/plain',
            headers={'Content-Length': str(len(caps_text))}
        )
        
    except Exception as e:
        logger.error(f"GetCACaps error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_pki_operation():
    """Handle PKIOperation - certificate enrollment/renewal"""
    try:
        logger.info("Handling PKIOperation request")
        
        # Get the PKCS#7 message from request body
        if not request.data:
            logger.error("No PKCS#7 message in request body")
            return jsonify({"error": "No PKCS#7 message provided"}), 400
            
        pkcs7_data = request.data
        logger.info(f"Received PKCS#7 message, size: {len(pkcs7_data)} bytes")
        
        # For now, return a simple response indicating the operation was received
        # In a full implementation, this would:
        # 1. Parse the PKCS#7 message
        # 2. Extract the CSR
        # 3. Validate the request
        # 4. Generate a certificate via EasyRSA
        # 5. Return a PKCS#7 response with the certificate
        
        logger.warning("PKIOperation received but not fully implemented yet")
        return jsonify({
            "status": "received",
            "message": "PKI operation received but processing not implemented",
            "size": len(pkcs7_data)
        }), 202
        
    except Exception as e:
        logger.error(f"PKIOperation error: {e}")
        return jsonify({"error": str(e)}), 500

def communicate_with_easyrsa(operation, params=None):
    """Helper function to communicate with EasyRSA container"""
    try:
        payload = {"operation": operation}
        if params:
            payload.update(params)
            
        response = requests.post(
            f"{EASYRSA_CONTAINER_URL}/execute",
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"EasyRSA communication failed: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"EasyRSA communication error: {e}")
        return None

@app.route('/debug')
def debug_info():
    """Debug endpoint for troubleshooting"""
    if not DEBUG_MODE:
        return jsonify({"error": "Debug mode disabled"}), 403
        
    try:
        # Test EasyRSA communication
        easyrsa_status = communicate_with_easyrsa("status")
        
        return jsonify({
            "scep_server_status": "running",
            "easyrsa_container_url": EASYRSA_CONTAINER_URL,
            "easyrsa_status": easyrsa_status,
            "ca_identifier": SCEP_CA_IDENTIFIER,
            "debug_mode": DEBUG_MODE,
            "supported_operations": SCEP_OPERATIONS,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Create logs directory
    os.makedirs('/app/logs', exist_ok=True)
    
    logger.info("Starting SCEP Server...")
    logger.info(f"EasyRSA Container URL: {EASYRSA_CONTAINER_URL}")
    logger.info(f"CA Identifier: {SCEP_CA_IDENTIFIER}")
    logger.info(f"Debug Mode: {DEBUG_MODE}")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=8090, debug=DEBUG_MODE)