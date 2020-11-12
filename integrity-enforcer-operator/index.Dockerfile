FROM quay.io/operator-framework/upstream-opm-builder AS builder

FROM centos


ARG USER_ID=1001
ARG GROUP_ID=12009

ENV USER opmuser
RUN groupadd -g ${GROUP_ID} ${USER} &&\
    useradd -g ${USER} -u ${USER_ID} -m ${USER} &&\
    usermod -aG wheel ${USER}


USER ${USER}
RUN whoami

LABEL operators.operatorframework.io.index.database.v1=/work/index.db

COPY --chown=opmuser:opmuser ["nsswitch.conf", "/etc/nsswitch.conf"]
COPY --chown=opmuser:opmuser ["database", "/work"]
COPY --chown=opmuser:opmuser  --from=builder /bin/opm /bin/opm
COPY --chown=opmuser:opmuser --from=builder /bin/grpc_health_probe /bin/grpc_health_probe

RUN chown  opmuser:opmuser /work/index.db &&\
    chown  opmuser:opmuser /bin/opm &&\
    chown  opmuser:opmuser /bin/grpc_health_probe &&\
    chown  opmuser:opmuser /etc/nsswitch.conf
  

EXPOSE 50051
USER 1001
WORKDIR /work

ENTRYPOINT ["/bin/opm"]
CMD ["registry", "serve", "--database", "index.db"]
