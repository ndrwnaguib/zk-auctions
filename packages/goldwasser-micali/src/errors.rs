/// Error type for generation of private/public keys.
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "length of public key modulus should be greater than 1")]
    LengthPublicKeyModulus,
    #[fail(display = "could not generate private/public keys")]
    CouldNotGenerateKeys,
}