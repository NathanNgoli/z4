FROM alpine:latest AS builder

RUN apk add --no-cache curl xz

RUN curl -fL https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz -o /tmp/zig.tar.xz && \
    tar -xJf /tmp/zig.tar.xz -C / && \
    mv /zig-x86_64-linux-0.15.2 /zig && \
    rm /tmp/zig.tar.xz

WORKDIR /build
COPY src ./src
COPY build.zig ./
COPY build.zig.zon ./

RUN /zig/zig build -Doptimize=ReleaseFast

FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /build/zig-out/bin/z4 /app/z4

RUN mkdir /app/data
VOLUME /app/data
EXPOSE 9670 9671

CMD ["/app/z4", "server"]
