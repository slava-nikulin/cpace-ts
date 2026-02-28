use curve25519_elligator2::MontgomeryPoint;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn elligator2_curve25519_u(rep: &[u8]) -> Result<Box<[u8]>, JsValue> {
    if rep.len() != 32 {
        return Err(JsValue::from_str("expected 32 bytes"));
    }

    let mut r = [0u8; 32];
    r.copy_from_slice(rep);

    let p: MontgomeryPoint = MontgomeryPoint::map_to_point_u255(&r);
    Ok(Box::new(p.0))
}
