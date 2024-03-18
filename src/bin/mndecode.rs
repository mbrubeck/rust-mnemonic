use std::io::Read;

fn main() -> mnemonic::Result<()> {
    let mut input = vec![];
    std::io::stdin().read_to_end(&mut input)?;
    mnemonic::decode(input, std::io::stdout())?;
    Ok(())
}
