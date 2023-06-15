FROM tinygo/tinygo:sha-598cb1e4ddce53d85600a1b7724ed39eea80e119 as build
WORKDIR /wasm
COPY wasm_add_header.go ./
RUN tinygo build -o ./wasm_add_header.go.wasm -scheduler=none -target=wasi -wasm-abi=generic ./wasm_add_header.go

FROM nginx@sha256:668c78547b869678d6be5ba9121b95975eab6a2db78dd722c8fba346d15ed723
COPY ./nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /wasm/wasm_add_header.go.wasm /usr/share/nginx/html/downloads
