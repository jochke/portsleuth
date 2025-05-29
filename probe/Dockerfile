FROM rockylinux:9

RUN groupadd -r psprobe && useradd -r -g psprobe psprobe
RUN dnf install -y python3 python3-pip nmap && dnf clean all

WORKDIR /app
COPY app.py requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

USER psprobe
ENTRYPOINT ["python3", "/app/app.py"]
VOLUME ["/data", "/var/log/portsleuth"]