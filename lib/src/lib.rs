#[feature(hacspec)]
mod hacspec {
    use edhoc_hacspec::*;
}

#[feature(not(hacspec))]
mod rust {
    use crate::*;
}
