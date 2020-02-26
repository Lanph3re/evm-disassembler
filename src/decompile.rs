use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

pub fn evm_decompile(input: Option<&str>) {
  let path = match input {
    Some(input_f) => Path::new(input_f),
    _ => panic!("How did you reach this code?!"),
  };

  let mut bytecode = match File::open(&path) {
    Err(why) => panic!("couldn't open {} {}", path.display(), why.description()),
    Ok(file) => file,
  };

  let mut s = String::new();
  match bytecode.read_to_string(&mut s) {
    Err(why) => panic!("couldn't read {}: {}", path.display(), why.description()),
    Ok(_) => print!("{} contains:\n{}", path.display(), s),
  }
}
