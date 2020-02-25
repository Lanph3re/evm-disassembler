extern crate clap;
use clap::{App, Arg};

fn main() {
    let matches = App::new("EVM Decompiler")
        .version("1.0")
        .author("Lanph3re <lanph3re@gmail.com>")
        .about("Decompile evm bytecodes to solidity code")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true)
                .index(1),
        )
        .get_matches();

    println!("Using input file: {}", matches.value_of("INPUT").unwrap());
}
