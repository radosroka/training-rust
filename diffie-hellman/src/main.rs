/// Diffie-Hellman Key Exchange demonstration.
///
/// Protocol overview:
///   1. Both parties agree on public parameters: prime `P` and generator `G`.
///   2. Each party picks a secret key and computes a public offer: G^secret mod P.
///   3. They exchange their public offers over an insecure channel.
///   4. Each party raises the received offer to their own secret: offer^secret mod P.
///   5. Both arrive at the same shared secret: G^(a*b) mod P, without ever
///      transmitting their secret keys.

/// Shared prime modulus (small value for demonstration; use a large safe prime in production).
const P: u64 = 23;
/// Primitive root modulo P used as the generator.
const G: u64 = 5;

/// Computes `g^a mod P` using exponentiation by squaring.
///
/// Intermediate values are widened to `u128` before each multiplication so
/// that products up to `(P-1)^2` never overflow, even for large `P`.
/// This avoids the silent wrong results that `g.pow(a) % P` produces once
/// `g^a` exceeds `u64::MAX`.
fn diffie_hellman(g: u64, a: u64) -> u64 {
    let mut result: u64 = 1;
    let mut base: u64 = g % P;
    let mut exp: u64 = a;

    while exp > 0 {
        if exp & 1 == 1 {
            // Widen to u128 to prevent overflow before reducing back to u64.
            result = (result as u128 * base as u128 % P as u128) as u64;
        }
        exp >>= 1;
        base = (base as u128 * base as u128 % P as u128) as u64;
    }
    result
}

/// Represents one participant in the key exchange.
#[derive(Debug)]
struct Person {
    name: String,
    /// The participant's private/secret key. Never shared.
    secret_key: u64,
    /// G^secret_key mod P — sent to the other party as the "public offer".
    public_offer: u64,
    /// The final shared secret: foreign_pk^secret_key mod P.
    /// Equals G^(a*b) mod P once both sides complete the exchange.
    public_key: u64,
    /// The public offer received from the other party.
    foreign_pk: u64,
}

impl Person {
    /// Creates a new participant with the given name and secret key.
    /// Immediately computes the public offer so it is ready to send.
    fn new(name: &str, sk: u64) -> Self {
        return Person {
            name: name.to_string(),
            secret_key: sk,
            public_offer: diffie_hellman(G, sk), // G^sk mod P
            public_key: 0,
            foreign_pk: 0,
        };
    }

    /// Sends this participant's public offer to `receiver`.
    /// Simulates transmitting the value over an (insecure) channel.
    fn send_pk(&self, receiver: &mut Person) {
        receiver.foreign_pk = self.public_offer;
    }

    /// Derives the shared secret from the received public offer and own secret key.
    /// Must be called after `foreign_pk` has been populated via `send_pk`.
    fn gen_pk(&mut self) {
        // foreign_pk^secret_key mod P == G^(other_secret * self_secret) mod P
        self.public_key = diffie_hellman(self.foreign_pk, self.secret_key);
    }

    /// Prints the full state of this participant for inspection.
    fn print(&self) {
        println!("{:?}", self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- constants ---

    #[test]
    fn test_p_is_prime() {
        // The protocol requires P to be prime for the math to hold.
        assert!(P >= 2, "P must be at least 2");
        for i in 2..P {
            assert_ne!(P % i, 0, "P = {} is divisible by {}", P, i);
        }
    }

    #[test]
    fn test_g_is_primitive_root_mod_p() {
        // G must be a primitive root (generator) of the multiplicative group mod P,
        // meaning G^k mod P cycles through every value in 1..P before repeating.
        let mut seen = std::collections::HashSet::new();
        let mut val = 1u64;
        for _ in 1..P {
            val = (val * G) % P;
            seen.insert(val);
        }
        assert_eq!(seen.len() as u64, P - 1,
            "G = {} is not a primitive root mod P = {}", G, P);
    }

    #[test]
    fn test_g_is_less_than_p() {
        assert!(G < P, "G must be less than P");
    }

    // --- diffie_hellman() ---

    #[test]
    fn test_no_overflow_for_large_exponent() {
        // 5^28 overflows u64 (~3.73e19 > u64::MAX ~1.84e19), so the naive
        // `g.pow(a) % P` gives a wrong answer. The squaring implementation
        // must still return the correct value.
        let expected = {
            // compute via u128 as ground truth
            let mut r: u128 = 1;
            for _ in 0..28 {
                r = r * 5 % 23;
            }
            r as u64
        };
        assert_eq!(diffie_hellman(5, 28), expected);
    }

    #[test]
    fn test_exchange_with_large_secret_keys() {
        // Secret keys large enough that the old g.pow(a) % P would overflow.
        let mut p1 = Person::new("P1", 28);
        let mut p2 = Person::new("P2", 31);

        p1.send_pk(&mut p2);
        p2.gen_pk();
        p2.send_pk(&mut p1);
        p1.gen_pk();

        assert_eq!(p1.public_key, p2.public_key);
    }

    #[test]
    fn test_modular_exponentiation_known_values() {
        // 5^1 mod 23 = 5
        assert_eq!(diffie_hellman(5, 1), 5);
        // 5^2 mod 23 = 25 mod 23 = 2
        assert_eq!(diffie_hellman(5, 2), 2);
        // 5^4 mod 23 = 625 mod 23 = 4
        assert_eq!(diffie_hellman(5, 4), 4);
    }

    #[test]
    fn test_exponent_zero_returns_one() {
        // Any base^0 mod P == 1
        assert_eq!(diffie_hellman(5, 0), 1);
    }

    // --- Person::new() ---

    #[test]
    fn test_new_computes_public_offer() {
        let alice = Person::new("Alice", 4);
        // public_offer should be G^4 mod 23 = 4
        assert_eq!(alice.public_offer, diffie_hellman(G, 4));
        // shared secret not yet computed
        assert_eq!(alice.public_key, 0);
        assert_eq!(alice.foreign_pk, 0);
    }

    // --- send_pk() ---

    #[test]
    fn test_send_pk_copies_offer_to_receiver() {
        let alice = Person::new("Alice", 4);
        let mut bob = Person::new("Bob", 3);
        alice.send_pk(&mut bob);
        assert_eq!(bob.foreign_pk, alice.public_offer);
    }

    #[test]
    fn test_send_pk_does_not_modify_sender() {
        let alice = Person::new("Alice", 4);
        let offer_before = alice.public_offer;
        let pk_before = alice.public_key;
        let mut bob = Person::new("Bob", 3);
        alice.send_pk(&mut bob);
        assert_eq!(alice.public_offer, offer_before);
        assert_eq!(alice.public_key, pk_before);
    }

    // --- gen_pk() ---

    #[test]
    fn test_gen_pk_computes_shared_secret() {
        let mut alice = Person::new("Alice", 4);
        let mut bob = Person::new("Bob", 3);

        alice.send_pk(&mut bob);
        bob.gen_pk();
        bob.send_pk(&mut alice);
        alice.gen_pk();

        // Both must converge on the same shared secret.
        assert_eq!(alice.public_key, bob.public_key);
        // G^(4*3) mod 23 = 5^12 mod 23 = 18
        assert_eq!(alice.public_key, 18);
    }

    // --- Full protocol ---

    #[test]
    fn test_exchange_is_symmetric_for_different_keys() {
        // Verify the protocol works for a different pair of secret keys.
        let mut p1 = Person::new("P1", 6);
        let mut p2 = Person::new("P2", 9);

        p1.send_pk(&mut p2);
        p2.gen_pk();
        p2.send_pk(&mut p1);
        p1.gen_pk();

        assert_eq!(p1.public_key, p2.public_key);
    }

    #[test]
    fn test_exchange_is_symmetric_for_equal_secret_keys() {
        // Edge case: both parties happen to choose the same secret key.
        let mut p1 = Person::new("P1", 5);
        let mut p2 = Person::new("P2", 5);

        p1.send_pk(&mut p2);
        p2.gen_pk();
        p2.send_pk(&mut p1);
        p1.gen_pk();

        assert_eq!(p1.public_key, p2.public_key);
    }

    #[test]
    fn test_exchange_secret_key_of_one() {
        // Edge case: secret key == 1 means public_offer == G^1 mod P == G.
        let mut p1 = Person::new("P1", 1);
        let mut p2 = Person::new("P2", 7);

        p1.send_pk(&mut p2);
        p2.gen_pk();
        p2.send_pk(&mut p1);
        p1.gen_pk();

        assert_eq!(p1.public_key, p2.public_key);
    }
}

fn main() {
    // Alice picks secret key 4, Bob picks secret key 3.
    // Each computes their own public offer internally on construction.
    let mut alice = Person::new("Alice", 4);
    let mut bob = Person::new("Bob", 3);

    // Step 1: Alice sends her public offer (G^4 mod P) to Bob.
    alice.send_pk(&mut bob);
    // Bob derives the shared secret: alice_offer^3 mod P == G^(4*3) mod P.
    bob.gen_pk();

    // Step 2: Bob sends his public offer (G^3 mod P) to Alice.
    bob.send_pk(&mut alice);
    // Alice derives the shared secret: bob_offer^4 mod P == G^(3*4) mod P.
    alice.gen_pk();

    // Both public_key fields should now hold the same value: G^12 mod 23 == 18.
    alice.print();
    bob.print();
}
