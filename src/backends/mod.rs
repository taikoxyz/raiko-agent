pub mod boundless;
pub mod brevis;
pub mod zisk;

#[cfg(test)]
mod brevis_provernet_config_tests {
    use super::*;

    #[test]
    fn brevis_provernet_config_example_deserializes() {
        let raw = include_str!("../../config/brevis_provernet_config.example.json");
        let config: brevis::BrevisProverNetConfig =
            serde_json::from_str(raw).expect("example brevis provernet config should deserialize");
        assert_eq!(config.chain_id, 8453);
        assert!(config.rpc_url.contains("base"));
    }
}
