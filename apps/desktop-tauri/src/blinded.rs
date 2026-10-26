//! Display-only fields of the blinded Spark regtest backend. Anything not
//! listed here is dropped before the webview, even if the backend supplies it.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub network: String,
    pub profile: String,
    pub status: String,
    #[serde(default)]
    pub blocked: Option<Blocked>,
    #[serde(default)]
    pub operation: Option<Operation>,
    pub denomination_sat: u64,
    pub public: PublicWallet,
    pub incognito: IncognitoWallet,
    pub activity: Vec<Activity>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Blocked {
    pub reason: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Operation {
    pub kind: String,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub coin: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicWallet {
    /// Absent while the Public wallet cannot be reached.
    pub address: Option<String>,
    pub total_sat: u64,
    pub leaves: Vec<PublicLeaf>,
    pub incoming: Vec<Incoming>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicLeaf {
    pub id: String,
    pub amount_sat: u64,
    pub available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Incoming {
    pub id: String,
    pub amount_sat: u64,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IncognitoWallet {
    pub address: String,
    pub total_sat: u64,
    pub coins: Vec<Coin>,
    pub incoming: Vec<Incoming>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Coin {
    pub id: String,
    pub amount_sat: u64,
    pub state: String,
    pub origin: String,
    pub can_send: bool,
    pub can_go_public: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub id: String,
    pub side: String,
    pub kind: String,
    pub label: String,
    pub amount_sat: u64,
    pub state: String,
    pub at: u64,
    #[serde(default)]
    pub counterparty: Option<String>,
}

/// Machine-readable progress. A `waiting` step may omit its position.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub operation: String,
    pub step: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub side: String,
    pub amount_sat: u64,
    pub change_sat: u64,
    pub fee_sat: u64,
    pub inputs: Vec<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    pub expected_ms: u64,
}
