


const P: u64 =  23;
const G: u64 = 5;

fn diffie_hellman(g: u64, a: u64) -> u64 {
    return (u64::pow(g,a as u32)) % P;
}

#[derive(Debug)]
struct Person {
    name: String,
    secret_key: u64,
    public_offer: u64,
    public_key: u64,
    foreign_pk: u64,
}

impl Person {
    fn new(name: &str, sk: u64) -> Self {
        return Person {
            name: name.to_string(),
            secret_key: sk,
            public_offer: diffie_hellman(G, sk),
            public_key: 0,
            foreign_pk: 0,
        }
    }

    fn send_pk(&self, receiver: &mut Person) {
        receiver.foreign_pk = self.public_offer;
    }

    fn gen_pk(&mut self) {
        self.public_key = diffie_hellman(self.foreign_pk, self.secret_key);
    }

    fn print(&self) {
        println!("{:?}", self);
    }
}

fn main() {

    let mut alice = Person::new("Alice", 4);
    let mut bob = Person::new("Bob", 3);

    alice.send_pk(&mut bob);
    bob.gen_pk();
    
    bob.send_pk(&mut alice);
    alice.gen_pk();
    
    alice.print();
    bob.print();    
}
