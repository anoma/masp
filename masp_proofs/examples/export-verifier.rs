use bls12_381::Bls12;
use bls12_381::Fp;
use bellman::groth16::Parameters;

// Extract the lowest 32 bytes of the base field element
fn lo_string(fp: Fp) -> String {
    let lo = &fp.to_bytes_le()[0..32];
    format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", lo[31], lo[30], lo[29], lo[28], lo[27], lo[26], lo[25], lo[24], lo[23], lo[22], lo[21], lo[20], lo[19], lo[18], lo[17], lo[16], lo[15], lo[14], lo[13], lo[12], lo[11], lo[10], lo[9], lo[8], lo[7], lo[6], lo[5], lo[4], lo[3], lo[2], lo[1], lo[0])
}

// Extract the highest 16 bytes of the base field element
fn hi_string(fp: Fp) -> String {
    let hi = &fp.to_bytes_le()[32..48];
    format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", hi[15], hi[14], hi[13], hi[12], hi[11], hi[10], hi[9], hi[8], hi[7], hi[6], hi[5], hi[4], hi[3], hi[2], hi[1], hi[0])
}

// Export Solidity verifier constants for use with verifier_groth16_bls12381.sol.ejs
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut params_file = std::fs::File::open(&args[1])
        .expect("unable to open verifier parameters");
    let params = Parameters::<Bls12>::read(&mut params_file, false)
        .expect("unable to open parameters");
    let alpha_g1_x = params.vk.alpha_g1.x();
    let alpha_g1_y = params.vk.alpha_g1.y();
    let beta_g2_x_c0 = params.vk.beta_g2.x().c0();
    let beta_g2_x_c1 = params.vk.beta_g2.x().c1();
    let beta_g2_y_c0 = params.vk.beta_g2.y().c0();
    let beta_g2_y_c1 = params.vk.beta_g2.y().c1();
    let gamma_g2_x_c0 = params.vk.gamma_g2.x().c0();
    let gamma_g2_x_c1 = params.vk.gamma_g2.x().c1();
    let gamma_g2_y_c0 = params.vk.gamma_g2.y().c0();
    let gamma_g2_y_c1 = params.vk.gamma_g2.y().c1();
    let delta_g2_x_c0 = params.vk.delta_g2.x().c0();
    let delta_g2_x_c1 = params.vk.delta_g2.x().c1();
    let delta_g2_y_c0 = params.vk.delta_g2.y().c0();
    let delta_g2_y_c1 = params.vk.delta_g2.y().c1();
    println!("// Scalar field size");
    println!("uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;");
    println!("// Base field size");
    println!("uint256 constant q0 = 45442060874369865957053122457065728162598490762543039060009208264153100167851;");
    println!("uint256 constant q1 = 34565483545414906068789196026815425751;");
    println!("// Verification Key data");
    println!("uint256 constant alphax0 = {};", lo_string(alpha_g1_x));
    println!("uint256 constant alphax1 = {};", hi_string(alpha_g1_x));
    println!("uint256 constant alphay0 = {};", lo_string(alpha_g1_y));
    println!("uint256 constant alphay1 = {};", hi_string(alpha_g1_y));
    println!("uint256 constant betax10 = {};", lo_string(beta_g2_x_c0));
    println!("uint256 constant betax11 = {};", hi_string(beta_g2_x_c0));
    println!("uint256 constant betax20 = {};", lo_string(beta_g2_x_c1));
    println!("uint256 constant betax21 = {};", hi_string(beta_g2_x_c1));
    println!("uint256 constant betay10 = {};", lo_string(beta_g2_y_c0));
    println!("uint256 constant betay11 = {};", hi_string(beta_g2_y_c0));
    println!("uint256 constant betay20 = {};", lo_string(beta_g2_y_c1));
    println!("uint256 constant betay21 = {};", hi_string(beta_g2_y_c1));
    println!("uint256 constant gammax10 = {};", lo_string(gamma_g2_x_c0));
    println!("uint256 constant gammax11 = {};", hi_string(gamma_g2_x_c0));
    println!("uint256 constant gammax20 = {};", lo_string(gamma_g2_x_c1));
    println!("uint256 constant gammax21 = {};", hi_string(gamma_g2_x_c1));
    println!("uint256 constant gammay10 = {};", lo_string(gamma_g2_y_c0));
    println!("uint256 constant gammay11 = {};", hi_string(gamma_g2_y_c0));
    println!("uint256 constant gammay20 = {};", lo_string(gamma_g2_y_c1));
    println!("uint256 constant gammay21 = {};", hi_string(gamma_g2_y_c1));
    println!("uint256 constant deltax10 = {};", lo_string(delta_g2_x_c0));
    println!("uint256 constant deltax11 = {};", hi_string(delta_g2_x_c0));
    println!("uint256 constant deltax20 = {};", lo_string(delta_g2_x_c1));
    println!("uint256 constant deltax21 = {};", hi_string(delta_g2_x_c1));
    println!("uint256 constant deltay10 = {};", lo_string(delta_g2_y_c0));
    println!("uint256 constant deltay11 = {};", hi_string(delta_g2_y_c0));
    println!("uint256 constant deltay20 = {};", lo_string(delta_g2_y_c1));
    println!("uint256 constant deltay21 = {};", hi_string(delta_g2_y_c1));
    for (i, ic) in params.vk.ic.iter().enumerate() {
        println!("uint256 constant IC{}x0 = {};", i, lo_string(ic.x()));
        println!("uint256 constant IC{}x1 = {};", i, hi_string(ic.x()));
        println!("uint256 constant IC{}y0 = {};", i, lo_string(ic.y()));
        println!("uint256 constant IC{}y1 = {};", i, hi_string(ic.y()));
    }
    println!("// Memory data");
    println!("uint16 constant pVk = 0;");
    println!("uint16 constant pPairing = 256;");
    println!("uint16 constant pLastMem = 1792;");
    println!("function verifyProof(uint[4] calldata _pA, uint[4][2] calldata _pB, uint[4] calldata _pC, uint[{}] calldata _pubSignals) public view returns (bool)", params.vk.ic.len()-1);
    println!("// Compute the linear combination vk_x");
    for i in 0..params.vk.ic.len()-1 {
        println!("g1_mulAccC(_pVk, IC{}x0, IC{}x1, IC{}y0, IC{}y1, calldataload(add(pubSignals, {})))", i+1, i+1, i+1, i+1, i*32);
    }
    println!("// Validate that all evaluations ∈ F");
    for i in 0..params.vk.ic.len()-1 {
        println!("checkField(calldataload(add(_pubSignals, {})))", i*32);
    }
}
