// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::error::Unspecified;

fn main() -> Result<(), Unspecified> {
    use aws_lc_rs::{
        kem::ML_KEM_512,
        kem::{Ciphertext, DecapsulationKey, EncapsulationKey},
    };

    // Alice generates their (private) decapsulation key.
    let decapsulation_key = DecapsulationKey::generate(&ML_KEM_512)?;

    // Alices computes the (public) encapsulation key.
    let encapsulation_key = decapsulation_key.encapsulation_key()?;

    let encapsulation_key_bytes = encapsulation_key.key_bytes()?;

    // Alice sends the encapsulation key bytes to bob through some
    // protocol message.
    let encapsulation_key_bytes = encapsulation_key_bytes.as_ref();

    // Bob constructs the (public) encapsulation key from the key bytes provided by Alice.
    let retrieved_encapsulation_key = EncapsulationKey::new(&ML_KEM_512, encapsulation_key_bytes)?;

    // Bob executes the encapsulation algorithm to to produce their copy of the secret, and associated ciphertext.
    let (ciphertext, bob_secret) = retrieved_encapsulation_key.encapsulate()?;

    // Alice receives ciphertext bytes from bob
    let ciphertext_bytes = ciphertext.as_ref();

    // Bob sends Alice the ciphertext computed from the encapsulation algorithm, Alice runs decapsulation to derive their
    // copy of the secret.
    let alice_secret = decapsulation_key.decapsulate(Ciphertext::from(ciphertext_bytes))?;

    // Alice and Bob have now arrived to the same secret
    assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());

    Ok(())
}
