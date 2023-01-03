/// RegistryRequest meant to initiate the dialog
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryRequest {
    /// not sure of the need, may want to resume on reconnect
    #[prost(bool, tag = "1")]
    pub full_sync: bool,
    /// not sure of the need, identifies the last update received, ignore if  full_sync = true
    #[prost(int32, tag = "2")]
    pub nonce: i32,
}
/// represents an update, a new/updated or removed credential
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryResponse {
    /// new or updated credentials
    #[prost(message, repeated, tag = "1")]
    pub credentials: ::prost::alloc::vec::Vec<registry_response::Credential>,
    /// removed ones (secret will be ignored)
    #[prost(message, repeated, tag = "2")]
    pub removals: ::prost::alloc::vec::Vec<registry_response::Credential>,
}
/// Nested message and enum types in `RegistryResponse`.
pub mod registry_response {
    /// A single credential
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Credential {
        /// identifies the owner of the credential
        #[prost(string, tag = "1")]
        pub owner: ::prost::alloc::string::String,
        /// the kind of credential, ideally a enum here, but keeping as a string make it more time-proof
        #[prost(string, tag = "2")]
        pub kind: ::prost::alloc::string::String,
        /// the client_id
        #[prost(string, tag = "3")]
        pub client_id: ::prost::alloc::string::String,
        /// secret if there is (e.g basic auth)
        #[prost(bytes = "vec", tag = "4")]
        pub secret: ::prost::alloc::vec::Vec<u8>,
    }
}
