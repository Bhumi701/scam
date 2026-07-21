import os
import sys
import time
import logging
from pyngrok import ngrok, conf

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scam_detector.ngrok")


def start_tunnel(port: int = 8000):
    """
    Starts an ngrok secure tunnel pointing to the local FastAPI port.
    Retrieves the authtoken from the NGROK_AUTHTOKEN environment variable if available.
    """
    logger.info("Initializing ngrok tunnel setup...")

    # Fetch authtoken from environment variables
    auth_token = os.environ.get("NGROK_AUTHTOKEN")
    
    if auth_token:
        logger.info("Found NGROK_AUTHTOKEN in environment variables. Configuring auth...")
        ngrok.set_auth_token(auth_token)
    else:
        logger.warning(
            "NGROK_AUTHTOKEN environment variable is not set. "
            "Free accounts may experience session limits. To set, run:\n"
            "export NGROK_AUTHTOKEN='your_token_here'"
        )

    try:
        # Start tunnel pointing to our FastAPI uvicorn port
        logger.info(f"Connecting secure ngrok tunnel to local port {port}...")
        public_url = ngrok.connect(port)
        
        # Clear print block to ensure the user notices the tunnel URL immediately
        print("=" * 70)
        print(" NGROK TUNNEL CREATED SUCCESSFULLY")
        print("=" * 70)
        print(f" Local API Port:   http://127.0.0.1:{port}")
        print(f" Public Tunnel:    {public_url}")
        print(f" API Swagger UI:   {public_url}/docs")
        print("=" * 70)
        print(" Press CTRL+C to terminate the tunnel and stop forwarding.")
        print("=" * 70)

        # Keep the process alive to monitor the tunnel
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n")
        logger.info("Shutting down secure tunnel gracefully...")
        try:
            ngrok.kill()
            logger.info("ngrok services stopped successfully.")
        except Exception as kill_err:
            logger.warning(f"Error killed during ngrok shutdown: {kill_err}")
            
    except Exception as e:
        logger.error(f"Failed to start ngrok tunnel: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Check for custom port override via system args
    target_port = 8000
    if len(sys.argv) > 1:
        try:
            target_port = int(sys.argv[1])
        except ValueError:
            logger.warning(f"Invalid port argument '{sys.argv[1]}'. Defaulting to 8000.")
            
    start_tunnel(port=target_port)