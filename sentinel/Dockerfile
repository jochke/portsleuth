FROM rockylinux:9

# Create non-root user\ nRUN groupadd -r psentry && useradd -r -g psentry psentry

# Install Python
RUN dnf install -y python3 python3-pip && dnf clean all

# Copy app
WORKDIR /app
COPY app.py requirements.txt entrypoint.sh ./

# Install deps
RUN pip3 install --no-cache-dir -r requirements.txt

# Hardening: drop caps, read-only FS
USER psentry
ENTRYPOINT ["/app/entrypoint.sh"]

# Restrict filesystem
VOLUME ["/var/log/portsleuth"]