/// The type of an identity provider instance.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub enum IdpType {
    #[default]
    Authentik,
}
