FROM ciscotalos/snort3:latest
ENV TZ=Europe/Bucharest

USER root

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-flask procps curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/snort-agent

COPY agent/agent.py /opt/snort-agent/agent.py
COPY agent/entrypoint.sh /opt/snort-agent/entrypoint.sh

RUN cp /home/snorty/snort3/bin/snort /usr/bin/snort
RUN chmod +x /opt/snort-agent/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/opt/snort-agent/entrypoint.sh"]
