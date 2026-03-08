fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("failed to locate protoc");
    // SAFETY: build scripts run single-process for this crate and setting PROTOC is required by tonic-build.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/smcp_gateway.proto"], &["proto"])
        .expect("failed to compile proto/smcp_gateway.proto");

    println!("cargo:rerun-if-changed=proto/smcp_gateway.proto");
}
