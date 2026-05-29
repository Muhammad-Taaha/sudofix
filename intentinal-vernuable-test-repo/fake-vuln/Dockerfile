# Dockerfile with Infrastructure as Code (IaC) Security Vulnerabilities
# This file contains intentional security misconfigurations for testing

# Vulnerability 1: Using latest tag (non-deterministic builds)
FROM ubuntu:latest

# Vulnerability 2: Running as root (no USER instruction)
# Vulnerability 3: Hardcoded secrets
ENV DATABASE_PASSWORD=SuperSecretPassword123
ENV API_KEY=sk-1234567890abcdefghijklmnop
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Vulnerability 4: Installing unnecessary packages that increase attack surface
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    telnet \
    ftp \
    ssh \
    sudo \
    vim \
    nano

# Vulnerability 5: Not using specific package versions
RUN apt-get install -y python3 python3-pip nodejs npm

# Vulnerability 6: Running update without cleanup (bloated image)
# No apt-get clean or rm -rf /var/lib/apt/lists/*

# Vulnerability 7: Using ADD instead of COPY for local files
ADD app.py /app/
ADD requirements.txt /app/

# Vulnerability 8: World-writable permissions
RUN chmod 777 /app
RUN chmod 777 /tmp

# Vulnerability 9: Exposing unnecessary ports
EXPOSE 22
EXPOSE 3306
EXPOSE 5432
EXPOSE 27017
EXPOSE 6379
EXPOSE 8080
EXPOSE 9000

# Vulnerability 10: Installing pip packages as root without verification
RUN pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org flask requests

# Vulnerability 11: Downloading and executing scripts from the internet
RUN curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

# Vulnerability 12: Setting insecure file permissions
RUN echo "root:password" | chpasswd

# Vulnerability 13: Leaving debugging tools in production image
RUN apt-get install -y gdb strace

# Vulnerability 14: Using apt with --allow-unauthenticated
RUN apt-get install -y --allow-unauthenticated some-package

# Vulnerability 15: No HEALTHCHECK defined
# (Missing healthcheck instruction)

# Vulnerability 16: Working directory with full permissions
WORKDIR /app
RUN chmod -R 777 /app

# Vulnerability 17: Running the application as root on privileged port
CMD ["python3", "/app/app.py"]

# Additional misconfigurations:
# - No multi-stage build
# - No image signing/verification
# - No resource limits
# - No security options
# - Secrets in environment variables
# - No vulnerability scanning in build process
