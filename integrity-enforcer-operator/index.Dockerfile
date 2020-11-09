FROM quay.io/operator-framework/upstream-opm-builder AS builder

FROM centos

ENV USER opmuser
RUN groupadd -g 12009 ${USER} &&\
    useradd -g ${USER} -u 1001 -m ${USER} &&\
    usermod -aG wheel ${USER}

USER ${USER}
RUN whoami

LABEL operators.operatorframework.io.index.database.v1=/work/index.db

COPY --chown=${USER} ["nsswitch.conf", "/etc/nsswitch.conf"]
COPY --chown=${USER} ["database", "/work"]
COPY --chown=${USER}  --from=builder /bin/opm /bin/opm
COPY --chown=${USER} --from=builder /bin/grpc_health_probe /bin/grpc_health_probe

RUN chown  ${USER}:${USER} /work/index.db &&\
    chown  ${USER}:${USER} /bin/opm &&\
    chown  ${USER}:${USER} /bin/grpc_health_probe &&\
    chown  ${USER}:${USER} /etc/nsswitch.conf
  

EXPOSE 50051
USER 1001
WORKDIR /work

ENTRYPOINT ["/bin/opm"]
CMD ["registry", "serve", "--database", "index.db"]
