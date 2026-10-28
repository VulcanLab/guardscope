# egress-jail: one-shot network-policy applier for T2/T3 (forced egress).
# Build context = ../targets (compose: context ../targets,
# dockerfile egress-jail/Dockerfile). Runs INSIDE the harness netns
# (compose: network_mode: "service:<harness>") with CAP_NET_ADMIN, applies
# the default-deny nftables output policy (apply.sh), and exits. See
# apply.sh for the policy and runner/run.py for the gating.
FROM alpine:3.22
RUN apk add --no-cache nftables
COPY egress-jail/apply.sh /apply.sh
RUN chmod +x /apply.sh
ENTRYPOINT ["/apply.sh"]
