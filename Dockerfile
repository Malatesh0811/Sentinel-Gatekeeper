FROM python:3.12-slim

# 1. Install System Tools
# We install gnupg and curl which are needed to setup the keys
RUN apt-get update && apt-get install -y \
    wget curl apt-transport-https gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Trivy (The Modern Way)
# apt-key is dead. We use gpg --dearmor and signed-by instead.
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install trivy -y

WORKDIR /app

# 3. Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install semgrep

# 4. Copy App Code
COPY app /app/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
