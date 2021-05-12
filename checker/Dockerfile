FROM ubuntu:18.04

RUN apt update && apt install -y curl 

RUN mkdir /app

COPY build/_bin/checker /app/checker

RUN chgrp -R 0 /app && chmod -R g=u /app

WORKDIR /app



ENTRYPOINT ["./checker"]


