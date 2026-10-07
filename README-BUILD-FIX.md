VPNSTAN v26 build fix

This package intentionally keeps start.sh at the project root so Railway/GitHub uploads cannot lose the scripts/ directory.
Dockerfile uses: COPY start.sh /start-vpnstan.sh

Keep this structure:
Dockerfile
start.sh
web/
railway.json
