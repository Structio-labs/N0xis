use std::hint::black_box;
pub trait Shape { fn area(&self) -> u64; fn name(&self) -> &'static str; }
pub struct Sq(pub u64);
pub struct Rect(pub u64, pub u64);
impl Shape for Sq { #[inline(never)] fn area(&self) -> u64 { self.0 * self.0 } fn name(&self) -> &'static str { "PLANTED_SQUARE" } }
impl Shape for Rect { #[inline(never)] fn area(&self) -> u64 { self.0 * self.1 } fn name(&self) -> &'static str { "PLANTED_RECT" } }
#[no_mangle] #[inline(never)] pub fn str_len_sum(a: &str, b: &[u8]) -> usize { a.len() + b.len() }
#[inline(never)] pub fn pick(i: usize) -> Box<dyn Shape> { if i == 0 { Box::new(Sq(3)) } else { Box::new(Rect(2, 5)) } }
#[inline(never)] pub fn checked(v: &[u64], i: usize) -> Result<u64, String> { if i < v.len() { Ok(v[i]) } else { Err(format!("PLANTED_ERROR {i}")) } }
#[inline(never)] pub fn boom(x: u64) -> u64 { if x == 7 { panic!("PLANTED_PANIC") } x + 1 }
fn main() {
    let i = black_box(std::env::args().count());
    let s = pick(i);
    println!("{} {} {}", s.name(), s.area(), str_len_sum(black_box("PLANTED_ALPHA"), black_box(b"PLANTED_BETA")));
    println!("{:?} {}", checked(&[1, 2], i), boom(i as u64));
}
