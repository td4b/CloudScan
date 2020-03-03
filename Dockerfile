FROM python:3.7.4

WORKDIR /app

RUN apt-get update && apt-get install -y python3 python3-pip && pip3 install virtualenv

RUN python3 -m virtualenv --python=/usr/bin/python3 /opt/venv

COPY ./source /app/.

RUN groupadd -g 1000 cloudscan \
    && useradd -m -u 1000 -g cloudscan cloudscan \
    && chown -R cloudscan:cloudscan /app

RUN ["chmod","+x","run.sh"]

RUN /bin/bash -c "source /opt/venv/bin/activate . && pip install -r requirements.txt"

USER cloudscan

ENTRYPOINT ["./run.sh"]
