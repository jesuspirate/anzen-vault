use super::{policy::ControllerPolicy, storage::VaultConfig, types::VaultUtxo};
use anyhow::{Context, Result, bail};
use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{Client as ElectrumClient, ConfigBuilder, ElectrumApi},
};
use bitcoin::{
    Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    blockdata::constants::genesis_block,
};
use bitcoincore_rpc::{
    Client, RpcApi,
    json::{GetBlockchainInfoResult, ScanTxOutRequest},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

pub const MAINNET_ELECTRUM_SERVERS: &[&str] = &[
    "ssl://bitcoin.lu.ke:50002",
    "ssl://electrum.blockstream.info:50002",
    "ssl://electrum.bullbitcoin.com:50002",
    "ssl://electrum.cakewallet.com:50002",
];

pub const REGTEST_ELECTRUM_SERVERS: &[&str] = &["tcp://127.0.0.1:50001"];
pub const SIGNET_ELECTRUM_SERVERS: &[&str] = &["ssl://mempool.space:60602"];
const ELECTRUM_TIMEOUT_SECONDS: u8 = 60;

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub url: String,
    pub user: String,
    pub password: String,
}

pub struct BitcoinCoreBackend {
    pub client: Client,
    network: Network,
}

pub struct ElectrumBackend {
    pub(crate) client: BdkElectrumClient<ElectrumClient>,
    server: String,
    network: Network,
}

#[derive(Debug, Clone)]
pub struct ChainTip {
    pub network: Network,
    pub height: u64,
    pub median_time: u64,
    pub best_block_hash: BlockHash,
}

/// The last block a watcher has read. If it is no longer on the best chain, the watcher starts
/// over from a fresh scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCursor {
    pub height: u64,
    pub block_hash: BlockHash,
}

/// A watcher's starting point: every unspent output paying a watched script at `cursor`.
#[derive(Debug, Clone)]
pub struct WatchBaseline {
    pub cursor: WatchCursor,
    pub coins: Vec<VaultUtxo>,
    /// Transactions already confirmed by `cursor` that touch a watched script. The watcher
    /// treats them as old news.
    pub history: Vec<Txid>,
}

/// A transaction that pays a watched script or spends a watched coin. `height` is `None` while
/// it waits in the mempool.
#[derive(Debug, Clone)]
pub struct WatchedTransaction {
    pub transaction: Transaction,
    pub height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct WatchActivity {
    pub cursor: WatchCursor,
    /// Confirmed transactions in chain order, then mempool transactions.
    pub transactions: Vec<WatchedTransaction>,
    /// False when the backend could not follow the chain block by block from the old cursor
    /// (a reorganisation, or a gap longer than it scans). The watcher then takes a new baseline.
    pub caught_up: bool,
}

/// A Bitcoin Core watcher reads every block since its cursor. After a longer gap (about a week)
/// it takes a fresh UTXO scan instead.
pub const WATCH_MAX_BLOCK_SCAN: u64 = 1_008;

pub trait Blockchain {
    fn network(&self) -> Network;
    fn backend_description(&self) -> String;
    fn chain_tip(&self) -> Result<ChainTip>;
    fn scan_vault(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>>;
    fn scan_connectors(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>>;
    /// Confirmed outputs paying a hard-locked savings address.
    fn scan_savings(&self, _address: &Address) -> Result<Vec<VaultUtxo>> {
        bail!("this chain backend cannot scan savings addresses")
    }
    fn broadcast(&self, transaction: &Transaction) -> Result<bitcoin::Txid>;
    /// Current fee rate in sat/vB for confirmation within `target_blocks`, or `None` when the
    /// backend has no estimate (for example a fresh regtest chain).
    fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<Option<u64>> {
        Ok(None)
    }
    /// Submit a parent and its fee-bumping child together. Backends without package relay
    /// broadcast them in order, which only works if the parent meets the mempool minimum alone.
    fn broadcast_package(&self, parent: &Transaction, child: &Transaction) -> Result<()> {
        self.broadcast(parent)?;
        self.broadcast(child)?;
        Ok(())
    }
    /// Every confirmed output paying one of `scripts`, and the block that scan describes.
    fn watch_baseline(&self, _scripts: &[ScriptBuf]) -> Result<WatchBaseline> {
        bail!("this chain backend cannot watch the vault")
    }
    /// Transactions since `since` that pay one of `scripts` or spend one of `coins`, plus mempool
    /// spends of `coins`. `handled` lists transactions the watcher already processed as
    /// confirmed; the backend may leave them out.
    fn watch_activity(
        &self,
        _scripts: &[ScriptBuf],
        _coins: &[OutPoint],
        _since: &WatchCursor,
        _handled: &HashSet<Txid>,
    ) -> Result<WatchActivity> {
        bail!("this chain backend cannot watch the vault")
    }
}

impl Blockchain for BitcoinCoreBackend {
    fn network(&self) -> Network {
        self.network
    }

    fn backend_description(&self) -> String {
        "Bitcoin Core RPC".to_owned()
    }

    fn chain_tip(&self) -> Result<ChainTip> {
        let info = self.chain_info()?;
        Ok(ChainTip {
            network: info.chain,
            height: info.blocks,
            median_time: info.median_time,
            best_block_hash: info.best_block_hash,
        })
    }

    fn scan_vault(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        BitcoinCoreBackend::scan_vault(self, config)
    }

    fn scan_connectors(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        BitcoinCoreBackend::scan_connectors(self, config)
    }

    fn scan_savings(&self, address: &Address) -> Result<Vec<VaultUtxo>> {
        if !address.as_unchecked().is_valid_for_network(self.network) {
            bail!("refusing to scan a savings address from another network");
        }
        self.scan_address(&address.to_string(), "savings")
    }

    fn broadcast(&self, transaction: &Transaction) -> Result<bitcoin::Txid> {
        match self.client.send_raw_transaction(transaction) {
            // A retry after a successful broadcast/failed local write may already be confirmed.
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
                error,
            ))) if error.code == -27 => Ok(transaction.compute_txid()),
            result => result.context("Bitcoin Core transaction broadcast failed"),
        }
    }

    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>> {
        let estimate = self
            .client
            .estimate_smart_fee(target_blocks, None)
            .context("Bitcoin Core fee estimation failed")?;
        Ok(estimate
            .fee_rate
            .and_then(|rate| super::fees::sat_per_vb_from_btc_per_kvb(rate.to_btc())))
    }

    fn broadcast_package(&self, parent: &Transaction, child: &Transaction) -> Result<()> {
        // `submitpackage` (Bitcoin Core 28+) accepts a low-fee parent when the child pays for both.
        let hex = [
            bitcoin::consensus::encode::serialize_hex(parent),
            bitcoin::consensus::encode::serialize_hex(child),
        ];
        let result: serde_json::Value = self
            .client
            .call("submitpackage", &[serde_json::json!(hex)])
            .context("Bitcoin Core package submission failed")?;
        match result.get("package_msg").and_then(|m| m.as_str()) {
            Some("success") => Ok(()),
            other => bail!(
                "Bitcoin Core rejected the fee-bump package: {}",
                other.unwrap_or("no message")
            ),
        }
    }

    fn watch_baseline(&self, scripts: &[ScriptBuf]) -> Result<WatchBaseline> {
        let requests = scripts
            .iter()
            .map(|script| ScanTxOutRequest::Single(format!("raw({})", script.to_hex_string())))
            .collect::<Vec<_>>();
        let result = self
            .client
            .scan_tx_out_set_blocking(&requests)
            .context("Bitcoin Core watcher scantxoutset failed")?;
        if result.success != Some(true) {
            bail!("Bitcoin Core did not complete the watcher's UTXO scan");
        }
        let cursor = WatchCursor {
            height: result
                .height
                .context("Bitcoin Core's UTXO scan did not report its height")?,
            block_hash: result
                .best_block_hash
                .context("Bitcoin Core's UTXO scan did not report its block")?,
        };
        let mut coins = result
            .unspents
            .into_iter()
            .map(|utxo| VaultUtxo {
                outpoint: OutPoint::new(utxo.txid, utxo.vout),
                txout: TxOut {
                    value: utxo.amount,
                    script_pubkey: utxo.script_pub_key,
                },
                confirmation_height: utxo.height,
            })
            .collect::<Vec<_>>();
        coins.sort_by_key(|utxo| (utxo.confirmation_height, utxo.outpoint));
        Ok(WatchBaseline {
            cursor,
            coins,
            history: Vec::new(),
        })
    }

    fn watch_activity(
        &self,
        scripts: &[ScriptBuf],
        coins: &[OutPoint],
        since: &WatchCursor,
        handled: &HashSet<Txid>,
    ) -> Result<WatchActivity> {
        let stale = WatchActivity {
            cursor: since.clone(),
            transactions: Vec::new(),
            caught_up: false,
        };
        let tip = self.chain_info()?.blocks;
        if since.height > tip
            || self
                .client
                .get_block_hash(since.height)
                .context("Bitcoin Core getblockhash failed")?
                != since.block_hash
            || tip - since.height > WATCH_MAX_BLOCK_SCAN
        {
            return Ok(stale);
        }
        let scripts = scripts.iter().collect::<HashSet<_>>();
        let mut coins = coins.iter().copied().collect::<HashSet<_>>();
        let mut cursor = since.clone();
        let mut transactions = Vec::new();
        for height in since.height + 1..=tip {
            let hash = self
                .client
                .get_block_hash(height)
                .context("Bitcoin Core getblockhash failed")?;
            let block = self
                .client
                .get_block(&hash)
                .context("Bitcoin Core getblock failed")?;
            if block.header.prev_blockhash != cursor.block_hash {
                // The chain changed under us; start over next time from a fresh scan.
                return Ok(stale);
            }
            for transaction in block.txdata {
                let spends = transaction
                    .input
                    .iter()
                    .any(|input| coins.contains(&input.previous_output));
                let pays = transaction
                    .output
                    .iter()
                    .any(|output| scripts.contains(&output.script_pubkey));
                if !spends && !pays {
                    continue;
                }
                for input in &transaction.input {
                    coins.remove(&input.previous_output);
                }
                let txid = transaction.compute_txid();
                for (vout, output) in transaction.output.iter().enumerate() {
                    if scripts.contains(&output.script_pubkey) {
                        coins.insert(OutPoint::new(txid, vout as u32));
                    }
                }
                transactions.push(WatchedTransaction {
                    transaction,
                    height: Some(height),
                });
            }
            cursor = WatchCursor {
                height,
                block_hash: hash,
            };
        }
        for txid in self.mempool_spends(&coins)? {
            if handled.contains(&txid) {
                continue;
            }
            let transaction = self
                .client
                .get_raw_transaction(&txid, None)
                .context("Bitcoin Core getrawtransaction failed for a mempool spend")?;
            transactions.push(WatchedTransaction {
                transaction,
                height: None,
            });
        }
        Ok(WatchActivity {
            cursor,
            transactions,
            caught_up: true,
        })
    }
}

impl ElectrumBackend {
    pub fn connect_default(network: Network) -> Result<Self> {
        let servers = match network {
            Network::Bitcoin => MAINNET_ELECTRUM_SERVERS,
            Network::Regtest => REGTEST_ELECTRUM_SERVERS,
            Network::Signet => SIGNET_ELECTRUM_SERVERS,
            other => bail!("unsupported Electrum network: {other}"),
        };
        Self::connect(network, servers)
    }

    pub fn connect(network: Network, servers: &[&str]) -> Result<Self> {
        if servers.is_empty() {
            bail!("no Electrum servers are configured for {network}");
        }
        let expected_genesis = genesis_block(network).block_hash();
        let mut errors = Vec::new();
        for server in servers {
            let attempt = (|| -> Result<Self> {
                // Without a timeout an unreachable server hangs the command instead of failing
                // over to the next one.
                let config = ConfigBuilder::new()
                    .timeout(Some(ELECTRUM_TIMEOUT_SECONDS))
                    .build();
                let raw = ElectrumClient::from_config(server, config)
                    .with_context(|| format!("could not connect to Electrum server {server}"))?;
                let genesis = raw
                    .block_header(0)
                    .with_context(|| format!("Electrum server {server} did not return genesis"))?
                    .block_hash();
                if genesis != expected_genesis {
                    bail!("Electrum server {server} is not on {network}");
                }
                Ok(Self {
                    client: BdkElectrumClient::new(raw),
                    server: (*server).to_owned(),
                    network,
                })
            })();
            match attempt {
                Ok(backend) => return Ok(backend),
                Err(error) => errors.push(format!("{server}: {error:#}")),
            }
        }
        bail!(
            "failed to connect to any Electrum server for {network}: {}",
            errors.join("; ")
        )
    }
}

impl Blockchain for ElectrumBackend {
    fn network(&self) -> Network {
        self.network
    }

    fn backend_description(&self) -> String {
        format!("Electrum ({})", self.server)
    }

    fn chain_tip(&self) -> Result<ChainTip> {
        let tip = self
            .client
            .inner
            .block_headers_subscribe()
            .context("Electrum header subscription failed")?;
        let first_height = tip.height.saturating_sub(10);
        let heights = (first_height..=tip.height)
            .map(|height| height as u32)
            .collect::<Vec<_>>();
        let mut times = self
            .client
            .inner
            .batch_block_header(heights.iter())
            .context("Electrum median-time-past header query failed")?
            .into_iter()
            .map(|header| u64::from(header.time))
            .collect::<Vec<_>>();
        times.sort_unstable();
        let median_time = times[times.len() / 2];
        Ok(ChainTip {
            network: self.network,
            height: tip.height as u64,
            median_time,
            best_block_hash: tip.header.block_hash(),
        })
    }

    fn scan_vault(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        if config.bitcoin_network()? != self.network {
            bail!(
                "refusing to scan a {} vault with {} Electrum",
                config.network,
                self.network
            );
        }
        let address = config
            .vault_address
            .parse::<Address<_>>()?
            .require_network(self.network)?;
        let script_pubkey = address.script_pubkey();
        self.scan_script(&script_pubkey, "vault")
    }

    fn scan_connectors(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        if config.bitcoin_network()? != self.network {
            bail!(
                "refusing to scan a {} vault with {} Electrum",
                config.network,
                self.network
            );
        }
        let controller = controller_policy(config)?;
        self.scan_script(&controller.address.script_pubkey(), "controller")
    }

    fn scan_savings(&self, address: &Address) -> Result<Vec<VaultUtxo>> {
        if !address.as_unchecked().is_valid_for_network(self.network) {
            bail!("refusing to scan a savings address from another network");
        }
        self.scan_script(&address.script_pubkey(), "savings")
    }

    fn broadcast(&self, transaction: &Transaction) -> Result<bitcoin::Txid> {
        let result = self.client.transaction_broadcast(transaction);
        if result.is_err() {
            let expected = transaction.compute_txid();
            // Do not infer acceptance from server-specific error strings. Ask the server for
            // the exact transaction, bypassing our local BDK transaction cache.
            if let Ok(known) = self.client.inner.transaction_get(&expected) {
                if known.compute_txid() == expected {
                    return Ok(expected);
                }
            }
        }
        result.context("Electrum transaction broadcast failed")
    }

    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>> {
        let btc_per_kvb = self
            .client
            .inner
            .estimate_fee(usize::from(target_blocks))
            .context("Electrum fee estimation failed")?;
        Ok(super::fees::sat_per_vb_from_btc_per_kvb(btc_per_kvb))
    }

    fn broadcast_package(&self, parent: &Transaction, child: &Transaction) -> Result<()> {
        // Electrum has no package relay: the parent must be accepted on its own first.
        self.broadcast(parent).context(
            "Electrum rejected the parent; a package-relay backend is needed to bump it",
        )?;
        self.broadcast(child)?;
        Ok(())
    }

    fn watch_baseline(&self, scripts: &[ScriptBuf]) -> Result<WatchBaseline> {
        let tip = self.chain_tip()?;
        let mut coins = Vec::new();
        let mut history = Vec::new();
        for script in scripts {
            coins.extend(
                self.scan_script(script, "watched")?
                    .into_iter()
                    .filter(|coin| coin.confirmation_height <= tip.height),
            );
            history.extend(
                self.client
                    .inner
                    .script_get_history(script)
                    .context("Electrum history query failed")?
                    .into_iter()
                    .filter(|item| item.height > 0 && item.height as u64 <= tip.height)
                    .map(|item| item.tx_hash),
            );
        }
        coins.sort_by_key(|utxo| (utxo.confirmation_height, utxo.outpoint));
        history.sort_unstable();
        history.dedup();
        Ok(WatchBaseline {
            cursor: WatchCursor {
                height: tip.height,
                block_hash: tip.best_block_hash,
            },
            coins,
            history,
        })
    }

    fn watch_activity(
        &self,
        scripts: &[ScriptBuf],
        _coins: &[OutPoint],
        since: &WatchCursor,
        handled: &HashSet<Txid>,
    ) -> Result<WatchActivity> {
        let tip = self.chain_tip()?;
        let on_chain = since.height <= tip.height
            && self
                .client
                .inner
                .block_header(since.height as usize)
                .context("Electrum block header query failed")?
                .block_hash()
                == since.block_hash;
        if !on_chain {
            return Ok(WatchActivity {
                cursor: since.clone(),
                transactions: Vec::new(),
                caught_up: false,
            });
        }
        // Electrum's script history lists every transaction that pays or spends a script.
        let mut wanted = Vec::new();
        for script in scripts {
            for item in self
                .client
                .inner
                .script_get_history(script)
                .context("Electrum history query failed")?
            {
                let height = (item.height > 0).then_some(item.height as u64);
                let new = height.is_none_or(|height| height > since.height && height <= tip.height);
                if new && !handled.contains(&item.tx_hash) {
                    wanted.push((height, item.tx_hash));
                }
            }
        }
        // Confirmed first, in height order, then the mempool.
        wanted.sort_by_key(|(height, txid)| (height.is_none(), *height, *txid));
        wanted.dedup();
        let mut transactions = Vec::with_capacity(wanted.len());
        for (height, txid) in wanted {
            let transaction = self
                .client
                .inner
                .transaction_get(&txid)
                .context("Electrum transaction query failed")?;
            transactions.push(WatchedTransaction {
                transaction,
                height,
            });
        }
        Ok(WatchActivity {
            cursor: WatchCursor {
                height: tip.height,
                block_hash: tip.best_block_hash,
            },
            transactions,
            caught_up: true,
        })
    }
}

impl ElectrumBackend {
    fn scan_script(&self, script_pubkey: &bitcoin::Script, label: &str) -> Result<Vec<VaultUtxo>> {
        let mut utxos = self
            .client
            .inner
            .script_list_unspent(script_pubkey)
            .with_context(|| format!("Electrum {label} UTXO query failed"))?
            .into_iter()
            .filter(|utxo| utxo.height > 0)
            .map(|utxo| VaultUtxo {
                outpoint: OutPoint::new(utxo.tx_hash, utxo.tx_pos as u32),
                txout: TxOut {
                    value: Amount::from_sat(utxo.value),
                    script_pubkey: script_pubkey.to_owned(),
                },
                confirmation_height: utxo.height as u64,
            })
            .collect::<Vec<_>>();
        utxos.sort_by_key(|utxo| (utxo.confirmation_height, utxo.outpoint));
        Ok(utxos)
    }
}

impl BitcoinCoreBackend {
    pub fn connect(config: &RpcConfig, expected_network: Network) -> Result<Self> {
        // Real CSV recovery tests intentionally mine tens of thousands of blocks. Core can
        // legitimately spend more than the jsonrpc crate's 15-second default on that request.
        let transport = bitcoincore_rpc::jsonrpc::simple_http::Builder::new()
            .url(&config.url)
            .with_context(|| format!("invalid Bitcoin Core RPC URL {}", config.url))?
            .auth(config.user.clone(), Some(config.password.clone()))
            .timeout(Duration::from_secs(300))
            .build();
        let client = Client::from_jsonrpc(
            bitcoincore_rpc::jsonrpc::client::Client::with_transport(transport),
        );
        let rpc = Self {
            client,
            network: expected_network,
        };
        rpc.chain_info()?;
        Ok(rpc)
    }

    pub fn chain_info(&self) -> Result<GetBlockchainInfoResult> {
        let info = self
            .client
            .get_blockchain_info()
            .context("Bitcoin Core getblockchaininfo failed")?;
        if info.chain != self.network {
            bail!(
                "Bitcoin Core network {} does not match requested network {}",
                info.chain,
                self.network
            );
        }
        Ok(info)
    }

    pub fn set_mock_time(&self, timestamp: u64) -> Result<()> {
        let _: serde_json::Value = self
            .client
            .call("setmocktime", &[serde_json::json!(timestamp)])
            .context("Bitcoin Core setmocktime failed")?;
        Ok(())
    }

    pub fn mine(&self, blocks: u64, address: &Address) -> Result<Vec<BlockHash>> {
        self.client
            .generate_to_address(blocks, address)
            .context("Bitcoin Core generatetoaddress failed")
    }

    pub fn scan_vault(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        if config.bitcoin_network()? != self.network {
            bail!(
                "refusing to scan a {} vault with {} Bitcoin Core RPC",
                config.network,
                self.network
            );
        }
        self.scan_address(&config.vault_address, "vault")
    }

    pub fn scan_connectors(&self, config: &VaultConfig) -> Result<Vec<VaultUtxo>> {
        if config.bitcoin_network()? != self.network {
            bail!(
                "refusing to scan a {} vault with {} Bitcoin Core RPC",
                config.network,
                self.network
            );
        }
        let controller = controller_policy(config)?;
        self.scan_address(&controller.address.to_string(), "controller")
    }

    fn scan_address(&self, address: &str, label: &str) -> Result<Vec<VaultUtxo>> {
        let request = ScanTxOutRequest::Single(format!("addr({address})"));
        let result = self
            .client
            .scan_tx_out_set_blocking(&[request])
            .with_context(|| format!("Bitcoin Core {label} scantxoutset failed"))?;
        if result.success != Some(true) {
            bail!("Bitcoin Core did not complete the {label} UTXO scan");
        }
        let mut utxos = result
            .unspents
            .into_iter()
            .map(|utxo| VaultUtxo {
                outpoint: OutPoint::new(utxo.txid, utxo.vout),
                txout: TxOut {
                    value: utxo.amount,
                    script_pubkey: utxo.script_pub_key,
                },
                confirmation_height: utxo.height,
            })
            .collect::<Vec<_>>();
        utxos.sort_by_key(|utxo| (utxo.confirmation_height, utxo.outpoint));
        Ok(utxos)
    }

    /// Mempool transactions spending any of `coins` (Bitcoin Core 24+ `gettxspendingprevout`).
    fn mempool_spends(&self, coins: &HashSet<OutPoint>) -> Result<Vec<Txid>> {
        if coins.is_empty() {
            return Ok(Vec::new());
        }
        let outputs = coins
            .iter()
            .map(|coin| serde_json::json!({ "txid": coin.txid.to_string(), "vout": coin.vout }))
            .collect::<Vec<_>>();
        let result: Vec<serde_json::Value> = self
            .client
            .call("gettxspendingprevout", &[serde_json::json!(outputs)])
            .context(
                "Bitcoin Core gettxspendingprevout failed (it needs Bitcoin Core 24 or newer)",
            )?;
        let mut spends = result
            .iter()
            .filter_map(|entry| entry.get("spendingtxid")?.as_str())
            .map(Txid::from_str)
            .collect::<Result<Vec<_>, _>>()
            .context("Bitcoin Core returned an invalid spending txid")?;
        spends.sort_unstable();
        spends.dedup();
        Ok(spends)
    }

    pub fn vault_balance(&self, config: &VaultConfig) -> Result<Amount> {
        let sats = self
            .scan_vault(config)?
            .into_iter()
            .map(|utxo| utxo.txout.value.to_sat())
            .sum();
        Ok(Amount::from_sat(sats))
    }
}

fn controller_policy(config: &VaultConfig) -> Result<ControllerPolicy> {
    let phone = crate::core::keys::VaultKey::from_str(&config.phone_vault_pubkey)
        .context("invalid configured phone vault key")?;
    let hww = crate::core::keys::VaultKey::from_str(&config.hww_vault_pubkey)
        .context("invalid configured HWW vault key")?;
    ControllerPolicy::new_for_network(phone, hww, config.bitcoin_network()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_config_keeps_explicit_connection_values() {
        let config = RpcConfig {
            url: "http://bitcoind:18443".to_owned(),
            user: "anzen".to_owned(),
            password: "secret".to_owned(),
        };
        assert_eq!(config.url, "http://bitcoind:18443");
        assert_eq!(config.user, "anzen");
        assert_eq!(config.password, "secret");
    }

    #[test]
    fn electrum_defaults_cover_public_mainnet_and_local_regtest() {
        assert!(MAINNET_ELECTRUM_SERVERS.contains(&"ssl://bitcoin.lu.ke:50002"));
        assert!(
            MAINNET_ELECTRUM_SERVERS
                .iter()
                .all(|server| server.starts_with("ssl://"))
        );
        assert_eq!(REGTEST_ELECTRUM_SERVERS, &["tcp://127.0.0.1:50001"]);
    }
}
