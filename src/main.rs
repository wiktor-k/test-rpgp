const DATA: &[u8] = b"Hello World";
use std::io::Cursor;
use std::io::Write;

use card_backend_pcsc::PcscBackend;
use openpgp_card::Card;
use pgp::crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
use pgp::packet::{self, SignatureConfig};
use pgp::types::{self, KeyId, KeyTrait, Mpi, PublicKeyTrait, SecretKeyTrait};
use unimpl::unimpl;

#[derive(Debug)]
struct CardSigner;

use rand::{CryptoRng, Rng};

impl KeyTrait for CardSigner {
    #[unimpl]
    fn fingerprint(&self) -> Vec<u8>;

    #[unimpl]
    fn key_id(&self) -> KeyId;

    #[unimpl]
    fn algorithm(&self) -> PublicKeyAlgorithm;
}

impl PublicKeyTrait for CardSigner {
    #[unimpl]
    fn verify_signature(
        &self,
        _hash: HashAlgorithm,
        _data: &[u8],
        _sig: &[Mpi],
    ) -> pgp::errors::Result<()>;

    #[unimpl]
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        _rng: &mut R,
        _plain: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>;

    #[unimpl]
    fn to_writer_old(&self, _writer: &mut impl std::io::Write) -> pgp::errors::Result<()>;
}

impl SecretKeyTrait for CardSigner {
    type PublicKey = ();

    fn unlock<F, G>(&self, _pw: F, _work: G) -> pgp::errors::Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&types::SecretKeyRepr) -> pgp::errors::Result<()>,
    {
        Ok(()) // already unlocked
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        _hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        let card = PcscBackend::cards(None)
            .expect("cards")
            .next()
            .unwrap()
            .expect("card");
        let mut card = Card::new(card).expect("card new");
        let mut tx = card.transaction().expect("tx");
        let pwd = &std::env::args().collect::<Vec<_>>()[1];
        eprintln!("with pwd = {pwd}");
        tx.verify_pw1_sign(pwd.as_bytes()).expect("Verify");
        let sig = tx.pso_compute_digital_signature(data.into()).expect("sig");

        Ok(vec![
            Mpi::from_raw_slice(&sig[..32]),
            Mpi::from_raw_slice(&sig[32..]),
        ])
    }

    #[unimpl]
    fn public_key(&self) -> Self::PublicKey;
}

fn main() -> testresult::TestResult {
    let signature = SignatureConfig::new_v4(
        packet::SignatureVersion::V4,
        packet::SignatureType::Binary,
        PublicKeyAlgorithm::EdDSA,
        HashAlgorithm::SHA2_256,
        vec![
            packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            packet::Subpacket::regular(packet::SubpacketData::Issuer(KeyId::from_slice(&[
                0x76, 0x7C, 0xE2, 0x24, 0xDB, 0x31, 0x1B, 0x3C,
            ])?)),
        ],
        vec![],
    );
    let signature = signature.sign(&CardSigner, String::new, DATA)?;

    let mut signature_bytes = Vec::with_capacity(1024);
    let mut buff = Cursor::new(&mut signature_bytes);
    packet::write_packet(&mut buff, &signature).expect("Write must succeed");

    std::fs::File::create("sig.pgp")
        .unwrap()
        .write_all(&signature_bytes)
        .unwrap();
    Ok(())
}
