fn main() -> Result<(), minreq::Error> {
    masp_proofs::download_masp_parameters(None).map(|_masp_paths| ())
}
