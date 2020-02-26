use clap::{App, Arg};
mod decompile;

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

    decompile::evm_decompile(matches.value_of("INPUT"));
}
