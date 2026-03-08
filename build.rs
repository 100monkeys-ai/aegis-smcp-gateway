fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate protoc");
    // SAFETY: build scripts run single-process for this crate and setting PROTOC is required by tonic-build.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let proto_dir = std::path::Path::new(&manifest_dir).join("aegis-proto/proto");
    let proto_file = proto_dir.join("smcp_gateway.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &[proto_file.to_str().expect("proto path is not valid UTF-8")],
            &[proto_dir.to_str().expect("include dir is not valid UTF-8")],
        )
        .expect("failed to compile smcp_gateway.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());
}
